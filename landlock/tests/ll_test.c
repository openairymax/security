// SPDX-License-Identifier: GPL-2.0-only
/*
 * ll_test.c — Landlock 用户态库的自包含 TAP 测试
 *
 * 职责：
 *   覆盖策略解析的正例与每类非法输入、
 *   handled 裁剪、规则数上限、重复释放与
 *   文件加载；Landlock 可用时额外 fork
 *   子进程验证「允许目录可写 / 未授权目录
 *   拒绝写入」两条运行期路径。施加策略不可逆，
 *   故运行期断言只在子进程内做，父进程按
 *   子进程退出码判负。内核不支持时整组以
 *   `ok N # SKIP landlock unavailable` 跳过。
 *
 * 文档锚点：
 *   docs/docs-linux/110-security/
 *   02-landlock-sandbox.md §7、§8
 */
#include "ll_api.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static int g_ok;
static int g_fail;

static void ok(int cond, const char *name)
{
	g_ok++;
	if (!cond) {
		g_fail++;
		printf("not ok %d - %s\n", g_ok, name);
		return;
	}
	printf("ok %d - %s\n", g_ok, name);
}

static void skip(const char *name, const char *why)
{
	g_ok++;
	printf("ok %d - %s # SKIP %s\n", g_ok, name, why);
}

static int parse_text(const char *text, struct ll_policy *pol)
{
	memset(pol, 0, sizeof(*pol));
	return ll_policy_parse(text, pol, NULL, 0);
}

static void expect_bad(const char *text, const char *name)
{
	struct ll_policy pol;
	char err[256] = "";
	int ret;

	memset(&pol, 0, sizeof(pol));
	ret = ll_policy_parse(text, &pol, err, sizeof(err));
	ok(ret == -EINVAL && err[0] != '\0', name);
	ll_policy_free(&pol);
}

static void test_parse(void)
{
	const char *text = "# 注释行\n\n   \nro /usr\n";
	struct ll_policy p;
	int ret;

	ret = parse_text(text, &p);
	ok(ret == 0 && p.nr == 1, "注释与空行被忽略");
	ok(ret == 0 && strcmp(p.rules[0].path, "/usr") == 0,
	   "规则路径保持不变");
	ok(p.handled == LL_DFL_HANDLED, "缺省 handled 生效");
	ll_policy_free(&p);
}

static void test_bits(void)
{
	const char *text =
		"handled read_file,read_dir,write_file,truncate,"
		"make_reg,execute\n"
		"ro /usr\n"
		"rw /work\n";
	struct ll_policy p;

	if (parse_text(text, &p) != 0) {
		ok(0, "ro/rw 访问位解析");
		return;
	}
	ok(p.rules[0].access == (LL_FS_READ_FILE | LL_FS_READ_DIR |
				 LL_FS_EXECUTE), "ro 授予读与执行");
	ok(p.rules[1].access == (LL_FS_READ_FILE | LL_FS_READ_DIR |
				 LL_FS_WRITE_FILE | LL_FS_TRUNCATE |
				 LL_FS_MAKE_REG), "rw 授予读与受控写集");
	ll_policy_free(&p);
}

static void test_trim(void)
{
	const char *text = "handled write_file,execute\nro /usr\nrw /work\n";
	struct ll_policy p;

	if (parse_text(text, &p) != 0) {
		ok(0, "handled 裁剪解析");
		return;
	}
	ok(p.rules[0].access == LL_FS_EXECUTE, "handled 裁剪 ro");
	ok(p.rules[1].access == LL_FS_WRITE_FILE, "handled 裁剪 rw");
	ll_policy_free(&p);
}

static void test_free(void)
{
	struct ll_policy p;

	if (parse_text("ro /usr\n", &p) != 0) {
		ok(0, "重复释放前解析");
		return;
	}
	ll_policy_free(&p);
	ll_policy_free(&p);
	ok(p.rules == NULL && p.nr == 0 && p.handled == 0,
	   "重复释放安全且清零");
	ll_policy_free(NULL);
	ok(1, "释放空指针安全");
}

static void test_load(void)
{
	char path[] = "/tmp/ll-load-XXXXXX";
	const char *text = "ro /usr\n";
	struct ll_policy p;
	char err[256] = "";
	int fd, ret;

	fd = mkstemp(path);
	if (fd < 0) {
		ok(0, "创建策略临时文件");
		return;
	}
	if (write(fd, text, strlen(text)) != (ssize_t)strlen(text)) {
		ok(0, "写入策略临时文件");
		close(fd);
		unlink(path);
		return;
	}
	close(fd);
	memset(&p, 0, sizeof(p));
	ret = ll_policy_load(path, &p, err, sizeof(err));
	ok(ret == 0 && p.nr == 1 && strcmp(p.rules[0].path, "/usr") == 0,
	   "load 读取并解析策略");
	ll_policy_free(&p);
	unlink(path);
	memset(&p, 0, sizeof(p));
	err[0] = '\0';
	ret = ll_policy_load("/nonexistent/ll-policy", &p, err,
			     sizeof(err));
	ok(ret < 0 && err[0] != '\0', "缺失策略文件返回可归因错误");
	ll_policy_free(&p);
}

static void test_bad(void)
{
	expect_bad("bogus /usr\n", "未知关键字判错");
	expect_bad("ro\n", "缺少路径判错");
	expect_bad("ro relative\n", "相对路径判错");
	expect_bad("ro /usr /lib\n", "多余参数判错");
	expect_bad("handled bogus\n", "未知 token 判错");
	expect_bad("handled execute\nhandled write_file\n",
		   "重复 handled 判错");
	expect_bad("handled ,\n", "空 handled 判错");
	expect_bad("handled execute\nrw /work\n",
		   "规则权限全被裁掉判错");
}

static void fill_rules(char *buf, size_t len, int nr)
{
	size_t off = 0;
	int i;

	for (i = 0; i < nr; i++) {
		if (off + 1 >= len)
			break;
		off += (size_t)snprintf(buf + off, len - off,
					"rw /p%d\n", i);
	}
}

static void test_limit(void)
{
	char buf[1024];
	struct ll_policy p;
	int ret;

	fill_rules(buf, sizeof(buf), LL_MAX_RULES);
	ret = parse_text(buf, &p);
	ok(ret == 0 && p.nr == LL_MAX_RULES, "64 条规则可解析");
	ll_policy_free(&p);
	fill_rules(buf, sizeof(buf), LL_MAX_RULES + 1);
	memset(&p, 0, sizeof(p));
	ret = ll_policy_parse(buf, &p, NULL, 0);
	ok(ret == -EINVAL, "65 条规则判错");
	ll_policy_free(&p);
}

/*
 * 子进程施加策略后写入 file：expect 非零
 * 要求成功，否则要求被拒绝。
 */
static int try_write(const struct ll_policy *pol, const char *file,
		     int expect)
{
	pid_t pid;
	int status;

	pid = fork();
	if (pid < 0)
		return 0;
	if (pid == 0) {
		int fd, err;

		if (ll_policy_apply(pol) < 0)
			_exit(10);
		fd = open(file, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
			  0600);
		err = errno;
		if (expect) {
			if (fd >= 0) {
				close(fd);
				_exit(0);
			}
			_exit(11);
		}
		if (fd >= 0) {
			close(fd);
			_exit(12);
		}
		_exit(err == EACCES || err == EPERM ? 0 : 13);
	}
	if (waitpid(pid, &status, 0) < 0)
		return 0;
	return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static void rm_paths(const char *f1, const char *f2, const char *d1,
		     const char *d2, const char *base)
{
	unlink(f1);
	unlink(f2);
	rmdir(d1);
	rmdir(d2);
	rmdir(base);
}

static void test_runtime(void)
{
	char tmpl[] = "/tmp/ll-run-XXXXXX";
	char allow[128], deny[128], file1[160], file2[160];
	char text[384];
	struct ll_policy p;
	int abi;

	abi = ll_sys_abi();
	if (abi <= 0) {
		skip("允许目录可写", "landlock unavailable");
		skip("未授权目录拒绝写入", "landlock unavailable");
		return;
	}
	if (mkdtemp(tmpl) == NULL) {
		ok(0, "创建运行期临时根");
		return;
	}
	snprintf(allow, sizeof(allow), "%s/allow", tmpl);
	snprintf(deny, sizeof(deny), "%s/deny", tmpl);
	snprintf(file1, sizeof(file1), "%s/probe", allow);
	snprintf(file2, sizeof(file2), "%s/probe", deny);
	if (mkdir(allow, 0700) < 0 || mkdir(deny, 0700) < 0) {
		ok(0, "创建运行期子目录");
		rm_paths(file1, file2, allow, deny, tmpl);
		return;
	}
	snprintf(text, sizeof(text),
		 "handled write_file,truncate,remove_file,remove_dir,"
		 "make_reg,make_dir\nrw %s\n", allow);
	if (parse_text(text, &p) != 0) {
		ok(0, "运行期策略解析");
		rm_paths(file1, file2, allow, deny, tmpl);
		return;
	}
	ok(try_write(&p, file1, 1), "允许目录可写");
	ok(try_write(&p, file2, 0), "未授权目录拒绝写入");
	ll_policy_free(&p);
	rm_paths(file1, file2, allow, deny, tmpl);
}

int main(void)
{
	printf("TAP version 13\n");
	test_parse();
	test_bits();
	test_trim();
	test_free();
	test_load();
	test_bad();
	test_limit();
	test_runtime();
	printf("1..%d\n", g_ok);
	return g_fail == 0 ? 0 : 1;
}
