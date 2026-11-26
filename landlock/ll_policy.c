// SPDX-License-Identifier: GPL-2.0-only
/*
 * ll_policy.c — Landlock 策略文本的加载与解析
 *
 * 职责：
 *   把 agent.conf 形态的文本解析为
 *   struct ll_policy。策略格式：
 *
 *     空行，以及首个非空白字符为 # 的行，
 *     都是注释。
 *     handled <token>[,<token>...]   可选，
 *     最多一次。
 *     ro <绝对路径>                  授予读位；
 *        handled 含 execute 时同时授予执行位。
 *     rw <绝对路径>                  授予读写全套，
 *        再按 handled 裁剪。
 *
 *   token 取值：
 *     write_file truncate remove_file remove_dir
 *     make_reg make_dir make_sock make_fifo
 *     make_block make_sym refer execute
 *     read_file read_dir
 *
 *   handled 缺省值见 LL_DFL_HANDLED：只限制写、
 *   删、建、改名与执行，读保持放行。因此缺省
 *   策略中的 ro 根实际只额外开放执行位。
 *
 *   规则请求的访问位按 handled 裁剪；裁剪后
 *   为空即判错，避免规则被静默丢弃。路径必须
 *   是绝对路径，规则数上限 LL_MAX_RULES。
 *   任何错误都返回 -EINVAL 并写入 err 缓冲区；
 *   分配失败返回 -ENOMEM。
 *
 * 文档锚点：
 *   docs/docs-linux/110-security/
 *   02-landlock-sandbox.md §5.1、§7
 */
#include "ll_api.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define ARRAY_SIZE(a)	(sizeof(a) / sizeof((a)[0]))

struct acc_name {
	const char *name;
	__u64 bit;
};

static const struct acc_name acc_tab[] = {
	{ "execute", LL_FS_EXECUTE },
	{ "write_file", LL_FS_WRITE_FILE },
	{ "read_file", LL_FS_READ_FILE },
	{ "read_dir", LL_FS_READ_DIR },
	{ "remove_dir", LL_FS_REMOVE_DIR },
	{ "remove_file", LL_FS_REMOVE_FILE },
	{ "make_char", LL_FS_MAKE_CHAR },
	{ "make_dir", LL_FS_MAKE_DIR },
	{ "make_reg", LL_FS_MAKE_REG },
	{ "make_sock", LL_FS_MAKE_SOCK },
	{ "make_fifo", LL_FS_MAKE_FIFO },
	{ "make_block", LL_FS_MAKE_BLOCK },
	{ "make_sym", LL_FS_MAKE_SYM },
	{ "refer", LL_FS_REFER },
	{ "truncate", LL_FS_TRUNCATE },
};

/*
 * 解析过程中的可变状态；规则类型与行号
 * 在收尾阶段与 handled 合算。
 */
struct parse_ctx {
	struct ll_policy *pol;
	unsigned char rw[LL_MAX_RULES];
	int line[LL_MAX_RULES];
	int handled_seen;
	char *err;
	size_t len;
};

static void set_err(char *err, size_t len, const char *fmt, ...)
	__attribute__((format(printf, 3, 4)));

static void set_err(char *err, size_t len, const char *fmt, ...)
{
	va_list ap;

	if (err == NULL || len == 0)
		return;
	va_start(ap, fmt);
	vsnprintf(err, len, fmt, ap);
	va_end(ap);
}

static void clear_err(char *err, size_t len)
{
	if (err != NULL && len > 0)
		err[0] = '\0';
}

static int tok_access(const char *name, __u64 *out)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(acc_tab); i++) {
		if (strcmp(name, acc_tab[i].name) == 0) {
			*out = acc_tab[i].bit;
			return 0;
		}
	}
	return -EINVAL;
}

static int parse_hdl(struct parse_ctx *ctx, char *arg, char *extra,
		     int line)
{
	char *save = NULL, *tok;
	__u64 mask = 0, bit;

	if (ctx->handled_seen) {
		set_err(ctx->err, ctx->len,
			"第 %d 行: handled 只能出现一次", line);
		return -EINVAL;
	}
	if (arg == NULL || extra != NULL) {
		set_err(ctx->err, ctx->len,
			"第 %d 行: handled 需要逗号分隔的 token 列表",
			line);
		return -EINVAL;
	}
	for (tok = strtok_r(arg, ",", &save); tok != NULL;
	     tok = strtok_r(NULL, ",", &save)) {
		if (tok_access(tok, &bit) < 0) {
			set_err(ctx->err, ctx->len,
				"第 %d 行: 未知访问 token %s", line, tok);
			return -EINVAL;
		}
		mask |= bit;
	}
	if (mask == 0) {
		set_err(ctx->err, ctx->len, "第 %d 行: handled 为空",
			line);
		return -EINVAL;
	}
	ctx->pol->handled = mask;
	ctx->handled_seen = 1;
	return 0;
}

static int add_rule(struct parse_ctx *ctx, char *arg, char *extra, int rw,
		    int line)
{
	char *copy;

	if (arg == NULL || extra != NULL) {
		set_err(ctx->err, ctx->len,
			"第 %d 行: %s 需要且仅需要一个路径",
			line, rw ? "rw" : "ro");
		return -EINVAL;
	}
	if (arg[0] != '/') {
		set_err(ctx->err, ctx->len,
			"第 %d 行: 路径必须是绝对路径: %s", line, arg);
		return -EINVAL;
	}
	if (ctx->pol->nr >= LL_MAX_RULES) {
		set_err(ctx->err, ctx->len,
			"第 %d 行: 规则数超过上限 %d", line, LL_MAX_RULES);
		return -EINVAL;
	}
	copy = strdup(arg);
	if (copy == NULL) {
		set_err(ctx->err, ctx->len, "第 %d 行: 内存不足", line);
		return -ENOMEM;
	}
	ctx->line[ctx->pol->nr] = line;
	ctx->rw[ctx->pol->nr] = rw ? 1 : 0;
	ctx->pol->rules[ctx->pol->nr].path = copy;
	ctx->pol->rules[ctx->pol->nr].access = 0;
	ctx->pol->nr++;
	return 0;
}

static int parse_line(struct parse_ctx *ctx, char *line, int lineno)
{
	char *save = NULL, *kw, *arg, *extra;

	kw = strtok_r(line, " \t\r", &save);
	if (kw == NULL || kw[0] == '#')
		return 0;
	arg = strtok_r(NULL, " \t\r", &save);
	extra = strtok_r(NULL, " \t\r", &save);
	if (strcmp(kw, "handled") == 0)
		return parse_hdl(ctx, arg, extra, lineno);
	if (strcmp(kw, "ro") == 0)
		return add_rule(ctx, arg, extra, 0, lineno);
	if (strcmp(kw, "rw") == 0)
		return add_rule(ctx, arg, extra, 1, lineno);
	set_err(ctx->err, ctx->len, "第 %d 行: 未知关键字 %s", lineno, kw);
	return -EINVAL;
}

/*
 * 收尾：按最终 handled 计算每条规则的访问位。
 * ro 只在 handled 含 execute 时追加执行位；
 * rw 请求读写全集后统一裁剪。
 */
static int finalize(struct parse_ctx *ctx)
{
	struct ll_policy *pol = ctx->pol;
	size_t i;

	for (i = 0; i < pol->nr; i++) {
		__u64 req = LL_FS_READ;

		if (ctx->rw[i])
			req = LL_FS_READ | LL_FS_WRITE;
		else if (pol->handled & LL_FS_EXECUTE)
			req |= LL_FS_EXECUTE;
		pol->rules[i].access = req & pol->handled;
		if (pol->rules[i].access == 0) {
			set_err(ctx->err, ctx->len,
				"第 %d 行: 规则权限不在 handled 内: %s",
				ctx->line[i], pol->rules[i].path);
			return -EINVAL;
		}
	}
	return 0;
}

int ll_policy_parse(const char *text, struct ll_policy *pol, char *err,
		    size_t len)
{
	struct parse_ctx ctx;
	char *buf, *line, *nl, *p;
	int ret = 0, lineno = 0;

	clear_err(err, len);
	if (text == NULL || pol == NULL)
		return -EINVAL;
	memset(pol, 0, sizeof(*pol));
	pol->handled = LL_DFL_HANDLED;
	pol->rules = calloc(LL_MAX_RULES, sizeof(*pol->rules));
	if (pol->rules == NULL) {
		set_err(err, len, "内存不足");
		return -ENOMEM;
	}
	buf = strdup(text);
	if (buf == NULL) {
		set_err(err, len, "内存不足");
		ll_policy_free(pol);
		return -ENOMEM;
	}
	memset(&ctx, 0, sizeof(ctx));
	ctx.pol = pol;
	ctx.err = err;
	ctx.len = len;
	for (p = buf; p != NULL; p = nl) {
		line = p;
		nl = strchr(p, '\n');
		if (nl != NULL)
			*nl++ = '\0';
		lineno++;
		ret = parse_line(&ctx, line, lineno);
		if (ret != 0)
			break;
	}
	if (ret == 0)
		ret = finalize(&ctx);
	free(buf);
	if (ret != 0)
		ll_policy_free(pol);
	return ret;
}

int ll_policy_load(const char *path, struct ll_policy *pol, char *err,
		   size_t len)
{
	char *buf = NULL;
	size_t cap = 0, used = 0;
	int fd, ret = 0;

	clear_err(err, len);
	if (path == NULL || pol == NULL)
		return -EINVAL;
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		int saved = errno;

		set_err(err, len, "无法打开策略文件 %s: %s",
			path, strerror(saved));
		return -saved;
	}
	for (;;) {
		ssize_t n;

		if (used + 1 >= cap) {
			size_t ncap = cap == 0 ? 4096 : cap * 2;
			char *nb = realloc(buf, ncap);

			if (nb == NULL) {
				set_err(err, len, "策略文件 %s 过大", path);
				ret = -ENOMEM;
				goto out;
			}
			buf = nb;
			cap = ncap;
		}
		n = read(fd, buf + used, cap - used - 1);
		if (n < 0) {
			int saved = errno;

			if (saved == EINTR)
				continue;
			set_err(err, len, "读取策略文件 %s 失败: %s",
				path, strerror(saved));
			ret = -saved;
			goto out;
		}
		if (n == 0)
			break;
		used += (size_t)n;
	}
	buf[used] = '\0';
	ret = ll_policy_parse(buf, pol, err, len);
out:
	free(buf);
	close(fd);
	return ret;
}

void ll_policy_free(struct ll_policy *pol)
{
	size_t i;

	if (pol == NULL)
		return;
	for (i = 0; pol->rules != NULL && i < pol->nr; i++)
		free(pol->rules[i].path);
	free(pol->rules);
	pol->rules = NULL;
	pol->nr = 0;
	pol->handled = 0;
}
