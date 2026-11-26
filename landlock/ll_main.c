// SPDX-License-Identifier: GPL-2.0-only
/*
 * ll_main.c — airy-landlock 命令行入口
 *
 * 职责：暴露 status / check / apply 三个子命令。
 *   status          打印内核 ABI（不支持时
 *                   abi=0），退出 0。
 *   check <policy>  仅解析并打印 rules/handled，
 *                   非法策略退出 3。
 *   apply <policy> <program> [args...]
 *                   解析、施加策略后 exec 目标程序。
 *                   退出码：2 用法错，3 策略非法，
 *                   4 内核不支持，5 施加失败，
 *                   127 exec 失败。
 *
 * 策略格式的完整说明由 --help 输出，
 * 与 ll_policy.c 的解析器逐条对应。
 *
 * 文档锚点：
 *   docs/docs-linux/110-security/
 *   02-landlock-sandbox.md §7、§8
 */
#include "ll_api.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define EX_USAGE	2
#define EX_POLICY	3
#define EX_UNSUP	4
#define EX_APPLY	5
#define EX_EXEC		127

static void usage(FILE *out)
{
	fputs("用法: airy-landlock <子命令> [参数...]\n"
	      "\n"
	      "子命令:\n"
	      "  status\n"
	      "      打印 abi=<n>；内核未启用 Landlock 时打印 abi=0。\n"
	      "  check <policy>\n"
	      "      仅解析策略，打印 rules=<n> handled=0x<hex>。\n"
	      "  apply <policy> <program> [args...]\n"
	      "      施加策略后执行 program。\n"
	      "\n"
	      "策略格式:\n"
	      "  空行与首个非空白字符为 # 的行为注释。\n"
	      "  handled <token>[,<token>...]   可选，最多一次。\n"
	      "  ro <绝对路径>                  "
	      "授予读位；handled 含 execute\n"
	      "                                 时同时授予执行位。\n"
	      "  rw <绝对路径>                  "
	      "授予读写全套，按 handled 裁剪。\n"
	      "\n"
	      "  token: write_file truncate remove_file remove_dir make_reg\n"
	      "         make_dir make_sock make_fifo make_block make_sym refer\n"
	      "         execute read_file read_dir\n"
	      "\n"
	      "  缺省 handled 只含写、删、建、改名、refer "
	      "与 execute，读\n"
	      "  保持放行。规则权限按 handled 裁剪，"
	      "裁剪后为空即判错。\n"
	      "  路径必须为绝对路径，规则数上限 64。\n"
	      "\n"
	      "退出码: 0 成功；2 用法错；3 策略非法；"
	      "4 内核不支持；\n"
	      "        5 施加失败；127 exec 失败。\n",
	      out);
}

static int usage_err(const char *msg)
{
	fprintf(stderr, "airy-landlock: %s\n", msg);
	usage(stderr);
	return EX_USAGE;
}

static int cmd_status(int argc)
{
	int abi;

	if (argc != 2)
		return usage_err("status 不接受额外参数");
	abi = ll_sys_abi();
	if (abi < 0)
		abi = 0;
	printf("abi=%d\n", abi);
	return 0;
}

static int cmd_check(int argc, char **argv)
{
	struct ll_policy pol;
	char err[256] = "";
	int ret;

	if (argc != 3)
		return usage_err("check 需要且仅需要一个策略文件");
	ret = ll_policy_load(argv[2], &pol, err, sizeof(err));
	if (ret < 0) {
		fprintf(stderr, "airy-landlock: %s\n",
			err[0] != '\0' ? err : "策略无效");
		return EX_POLICY;
	}
	printf("rules=%zu handled=0x%llx\n", pol.nr,
	       (unsigned long long)pol.handled);
	ll_policy_free(&pol);
	return 0;
}

static int cmd_apply(int argc, char **argv)
{
	struct ll_policy pol;
	char err[256] = "";
	int ret;

	if (argc < 4)
		return usage_err("apply 需要策略文件与要执行的程序");
	ret = ll_policy_load(argv[2], &pol, err, sizeof(err));
	if (ret < 0) {
		fprintf(stderr, "airy-landlock: %s\n",
			err[0] != '\0' ? err : "策略无效");
		return EX_POLICY;
	}
	ret = ll_policy_apply(&pol);
	ll_policy_free(&pol);
	if (ret == -ENOTSUP) {
		fprintf(stderr, "airy-landlock: 内核不支持 Landlock\n");
		return EX_UNSUP;
	}
	if (ret < 0) {
		fprintf(stderr, "airy-landlock: 施加策略失败: %s\n",
			strerror(-ret));
		return EX_APPLY;
	}
	execvp(argv[3], &argv[3]);
	fprintf(stderr, "airy-landlock: exec %s 失败: %s\n",
		argv[3], strerror(errno));
	return EX_EXEC;
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		usage(stderr);
		return EX_USAGE;
	}
	if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
		usage(stdout);
		return 0;
	}
	if (strcmp(argv[1], "status") == 0)
		return cmd_status(argc);
	if (strcmp(argv[1], "check") == 0)
		return cmd_check(argc, argv);
	if (strcmp(argv[1], "apply") == 0)
		return cmd_apply(argc, argv);
	fprintf(stderr, "airy-landlock: 未知子命令 %s\n", argv[1]);
	usage(stderr);
	return EX_USAGE;
}
