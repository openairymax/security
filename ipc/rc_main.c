// SPDX-License-Identifier: GPL-2.0-only
/*
 * rc_main.c — airy-reconcile CLI
 *
 * 职责：
 *   从控制面快照文件与数据面扫描文件读取输入，
 *   调用 rc_run 完成一次 Reconciliation，并把
 *   执行后的计数打印到 stdout。ops 回调只把动作
 *   边界写到 stdout，不伪造后端成功。
 *
 * 文件格式与文档锚点：
 * docs/docs-linux/110-security/
 * 05-ipc-control-plane-reconciliation.md §2。
 */
#include "rc_api.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

struct file_data {
	struct rc_ring rings[RC_MAX_ENTRIES];
	size_t nr_rings;
	struct rc_cap caps[RC_MAX_ENTRIES];
	size_t nr_caps;
	struct rc_msg msgs[RC_MAX_ENTRIES];
	size_t nr_msgs;
};

static int g_have_now;
static __u64 g_now;

static void usage(FILE *out)
{
	fputs("用法: airy-reconcile --state <file> --scan <file>"
	      " [--now <ns>]\n", out);
	fputs("  --state  控制面快照文件\n", out);
	fputs("  --scan   数据面扫描结果文件\n", out);
	fputs("  --now    注入时钟读数(ns)，缺省取系统时钟\n", out);
	fputs("控制面文件格式:\n", out);
	fputs("  ring <id> <state>\n", out);
	fputs("  cap <id> <state> <verified>\n", out);
	fputs("  msg <ring> <kind> <ts_ns>\n", out);
	fputs("    kind = normal | cap | ctrl\n", out);
	fputs("数据面文件格式:\n", out);
	fputs("  ring <id> <state>\n", out);
	fputs("  cap <id> <state> <verified>\n", out);
	fputs("  '#' 起首为注释，空行忽略\n", out);
}

static int parse_ring(const char *rest, struct file_data *fd)
{
	unsigned id;
	unsigned state;
	char extra[8];

	if (sscanf(rest, "%u %u %7s", &id, &state, extra) != 2)
		return -EINVAL;
	if (state > 0xffu)
		return -EINVAL;
	if (fd->nr_rings >= RC_MAX_ENTRIES)
		return -E2BIG;
	fd->rings[fd->nr_rings].id = id;
	fd->rings[fd->nr_rings].state = (__u8)state;
	fd->nr_rings++;
	return 0;
}

static int parse_cap(const char *rest, struct file_data *fd)
{
	unsigned id;
	unsigned state;
	unsigned verified;
	char extra[8];

	if (sscanf(rest, "%u %u %u %7s", &id, &state, &verified, extra) != 3)
		return -EINVAL;
	if (state > 0xffu || verified > 1u)
		return -EINVAL;
	if (fd->nr_caps >= RC_MAX_ENTRIES)
		return -E2BIG;
	fd->caps[fd->nr_caps].id = id;
	fd->caps[fd->nr_caps].state = (__u8)state;
	fd->caps[fd->nr_caps].verified = (__u8)verified;
	fd->nr_caps++;
	return 0;
}

static int parse_kind(const char *s, __u8 *kind)
{
	if (strcmp(s, "normal") == 0)
		*kind = RC_MSG_NORMAL;
	else if (strcmp(s, "cap") == 0)
		*kind = RC_MSG_CAP;
	else if (strcmp(s, "ctrl") == 0)
		*kind = RC_MSG_CTRL;
	else
		return -EINVAL;
	return 0;
}

static int parse_msg(const char *rest, struct file_data *fd)
{
	unsigned ring;
	char kind[8];
	unsigned long long ts;
	char extra[8];
	__u8 id;
	int ret;

	if (sscanf(rest, "%u %7s %llu %7s", &ring, kind, &ts, extra) != 3)
		return -EINVAL;
	ret = parse_kind(kind, &id);
	if (ret < 0)
		return ret;
	if (fd->nr_msgs >= RC_MAX_ENTRIES)
		return -E2BIG;
	fd->msgs[fd->nr_msgs].ring = ring;
	fd->msgs[fd->nr_msgs].kind = id;
	fd->msgs[fd->nr_msgs].ts_ns = ts;
	fd->nr_msgs++;
	return 0;
}

static int parse_line(char *line, struct file_data *fd, int allow_msg)
{
	char kw[16];
	char *p = line;
	int off = 0;

	while (*p == ' ' || *p == '\t')
		p++;
	if (*p == '\n' || *p == '\r' || *p == '\0' || *p == '#')
		return 0;
	if (sscanf(p, "%15s%n", kw, &off) != 1)
		return -EINVAL;
	p += off;
	if (strcmp(kw, "ring") == 0)
		return parse_ring(p, fd);
	if (strcmp(kw, "cap") == 0)
		return parse_cap(p, fd);
	if (strcmp(kw, "msg") == 0 && allow_msg)
		return parse_msg(p, fd);
	return -EINVAL;
}

static int load_file(const char *path, int allow_msg, struct file_data *fd)
{
	FILE *fp = fopen(path, "r");
	char *line = NULL;
	size_t cap = 0;
	unsigned long no = 0;
	int ret = 0;
	int err;

	if (fp == NULL) {
		fprintf(stderr, "airy-reconcile: 无法打开 %s\n", path);
		return -ENOENT;
	}
	memset(fd, 0, sizeof(*fd));
	while (getline(&line, &cap, fp) >= 0) {
		no++;
		ret = parse_line(line, fd, allow_msg);
		if (ret < 0) {
			fprintf(stderr, "%s:%lu: %s\n", path, no,
				ret == -E2BIG ? "条目超过上限"
					      : "格式错误");
			break;
		}
	}
	err = ferror(fp);
	free(line);
	fclose(fp);
	if (ret == 0 && err)
		ret = -EIO;
	return ret;
}

static int op_ring_rec(__u32 id)
{
	printf("ring_rec id=%u\n", (unsigned)id);
	return 0;
}

static int op_ring_drop(__u32 id)
{
	printf("ring_drop id=%u\n", (unsigned)id);
	return 0;
}

static int op_ring_adopt(__u32 id, __u8 state)
{
	printf("ring_adopt id=%u state=%u\n", (unsigned)id,
	       (unsigned)state);
	return 0;
}

static int op_cap_check(__u32 id)
{
	printf("cap_check id=%u\n", (unsigned)id);
	return 0;
}

static int op_cap_revoke(__u32 id)
{
	printf("cap_revoke id=%u\n", (unsigned)id);
	return 0;
}

static int op_msg_send(__u32 ring, __u64 ts)
{
	printf("msg_send ring=%u ts_ns=%llu\n", (unsigned)ring,
	       (unsigned long long)ts);
	return 0;
}

static int op_msg_drop(__u32 ring, __u64 ts)
{
	printf("msg_drop ring=%u ts_ns=%llu\n", (unsigned)ring,
	       (unsigned long long)ts);
	return 0;
}

static void op_degrade(int why)
{
	printf("degrade why=%d\n", why);
}

static const struct rc_ops cli_ops = {
	.ring_rec = op_ring_rec,
	.ring_drop = op_ring_drop,
	.ring_adopt = op_ring_adopt,
	.cap_check = op_cap_check,
	.cap_revoke = op_cap_revoke,
	.msg_send = op_msg_send,
	.msg_drop = op_msg_drop,
	.degrade = op_degrade,
};

static __u64 cli_now(void)
{
	struct timespec ts;

	if (g_have_now)
		return g_now;
	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		return 0;
	return (__u64)ts.tv_sec * 1000000000ULL + (__u64)ts.tv_nsec;
}

static int parse_args(int argc, char **argv, const char **state_path,
		      const char **scan_path)
{
	int i;

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--help") == 0 ||
		    strcmp(argv[i], "-h") == 0) {
			usage(stdout);
			return 1;
		}
		if (strcmp(argv[i], "--state") == 0 && i + 1 < argc) {
			*state_path = argv[++i];
		} else if (strcmp(argv[i], "--scan") == 0 &&
			   i + 1 < argc) {
			*scan_path = argv[++i];
		} else if (strcmp(argv[i], "--now") == 0 &&
			   i + 1 < argc) {
			char *end = NULL;
			unsigned long long v;

			v = strtoull(argv[++i], &end, 10);
			if (end == argv[i] || *end != '\0')
				return -1;
			g_have_now = 1;
			g_now = (__u64)v;
		} else {
			return -1;
		}
	}
	if (*state_path == NULL || *scan_path == NULL)
		return -1;
	return 0;
}

static void fill_ctx(struct rc_ctx *ctx, const struct file_data *state,
		     const struct file_data *scan)
{
	memset(ctx, 0, sizeof(*ctx));
	ctx->state_rings = state->rings;
	ctx->state_rings_nr = state->nr_rings;
	ctx->state_caps = state->caps;
	ctx->state_caps_nr = state->nr_caps;
	ctx->msgs = state->msgs;
	ctx->msgs_nr = state->nr_msgs;
	ctx->scan_rings = scan->rings;
	ctx->scan_rings_nr = scan->nr_rings;
	ctx->scan_caps = scan->caps;
	ctx->scan_caps_nr = scan->nr_caps;
	ctx->ops = &cli_ops;
	ctx->now_ns = cli_now;
}

static void print_report(const struct rc_report *rep)
{
	printf("rings_new=%u rings_miss=%u rings_conf=%u "
	       "caps_verify=%u caps_revoke=%u msg_sent=%u "
	       "msg_drop=%u degrade=%u\n",
	       (unsigned)rep->rings_new, (unsigned)rep->rings_miss,
	       (unsigned)rep->rings_conf, (unsigned)rep->caps_verify,
	       (unsigned)rep->caps_revoke, (unsigned)rep->msg_sent,
	       (unsigned)rep->msg_drop, (unsigned)rep->degrade);
}

int main(int argc, char **argv)
{
	const char *state_path = NULL;
	const char *scan_path = NULL;
	struct file_data *state;
	struct file_data *scan;
	struct rc_ctx ctx;
	int ret;

	ret = parse_args(argc, argv, &state_path, &scan_path);
	if (ret == 1)
		return 0;
	if (ret < 0) {
		usage(stderr);
		return 2;
	}
	state = calloc(1, sizeof(*state));
	scan = calloc(1, sizeof(*scan));
	if (state == NULL || scan == NULL) {
		free(state);
		free(scan);
		return 4;
	}
	if (load_file(state_path, 1, state) < 0 ||
	    load_file(scan_path, 0, scan) < 0) {
		free(state);
		free(scan);
		return 3;
	}
	fill_ctx(&ctx, state, scan);
	ret = rc_run(&ctx);
	if (ret == -E2BIG) {
		fprintf(stderr, "airy-reconcile: 输入超过上限\n");
		free(state);
		free(scan);
		return 3;
	}
	if (ret < 0) {
		fprintf(stderr, "airy-reconcile: 执行失败 %d\n", ret);
		free(state);
		free(scan);
		return 4;
	}
	print_report(&ctx.report);
	free(state);
	free(scan);
	return 0;
}
