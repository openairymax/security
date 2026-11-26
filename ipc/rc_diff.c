// SPDX-License-Identifier: GPL-2.0-only
/*
 * rc_diff.c — Ring 与 Capability 差异检测
 *
 * 职责：
 *   把控制面快照与数据面扫描结果按 id 排序、
 *   去重，再用归并双指针生成稳定差异序列。
 *   Ring：数据面独有 NEW、控制面独有 MISS、
 *   双方状态不同 CONF；Capability：数据面未
 *   校验 VERIFY、控制面已 REVOKED 而数据面未
 *   撤销 REVOKE。输入超容量返回 -E2BIG。
 *
 * 文档锚点：
 * docs/docs-linux/110-security/
 * 05-ipc-control-plane-reconciliation.md §3。
 */
#include "rc_internal.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

static int ring_cmp(const void *l, const void *r)
{
	const struct rc_ring *a = l;
	const struct rc_ring *b = r;

	if (a->id != b->id)
		return a->id < b->id ? -1 : 1;
	if (a->state != b->state)
		return a->state < b->state ? -1 : 1;
	return 0;
}

static int cap_cmp(const void *l, const void *r)
{
	const struct rc_cap *a = l;
	const struct rc_cap *b = r;

	if (a->id != b->id)
		return a->id < b->id ? -1 : 1;
	if (a->state != b->state)
		return a->state < b->state ? -1 : 1;
	if (a->verified != b->verified)
		return a->verified < b->verified ? -1 : 1;
	return 0;
}

static int diff_cmp(const void *l, const void *r)
{
	const struct rc_diff *a = l;
	const struct rc_diff *b = r;

	if (a->id != b->id)
		return a->id < b->id ? -1 : 1;
	if (a->type != b->type)
		return a->type < b->type ? -1 : 1;
	return 0;
}

static int copy_rings(const struct rc_ring *src, size_t nr,
		      struct rc_ring **dst, size_t *dst_nr)
{
	struct rc_ring *p = NULL;

	if (nr > 0 && src == NULL)
		return -EINVAL;
	if (nr > 0) {
		p = malloc(nr * sizeof(*p));
		if (p == NULL)
			return -ENOMEM;
		memcpy(p, src, nr * sizeof(*p));
		qsort(p, nr, sizeof(*p), ring_cmp);
	}
	*dst = p;
	*dst_nr = nr;
	return 0;
}

static int copy_caps(const struct rc_cap *src, size_t nr,
		     struct rc_cap **dst, size_t *dst_nr)
{
	struct rc_cap *p = NULL;

	if (nr > 0 && src == NULL)
		return -EINVAL;
	if (nr > 0) {
		p = malloc(nr * sizeof(*p));
		if (p == NULL)
			return -ENOMEM;
		memcpy(p, src, nr * sizeof(*p));
		qsort(p, nr, sizeof(*p), cap_cmp);
	}
	*dst = p;
	*dst_nr = nr;
	return 0;
}

void rc_scan_free(struct rc_scan *scan)
{
	free(scan->state_rings);
	free(scan->scan_rings);
	free(scan->state_caps);
	free(scan->scan_caps);
	memset(scan, 0, sizeof(*scan));
}

int rc_scan_build(const struct rc_ctx *ctx, struct rc_scan *scan)
{
	int ret;

	memset(scan, 0, sizeof(*scan));
	if (ctx->state_rings_nr > RC_MAX_ENTRIES ||
	    ctx->state_caps_nr > RC_MAX_ENTRIES ||
	    ctx->scan_rings_nr > RC_MAX_ENTRIES ||
	    ctx->scan_caps_nr > RC_MAX_ENTRIES)
		return -E2BIG;

	ret = copy_rings(ctx->state_rings, ctx->state_rings_nr,
			 &scan->state_rings, &scan->state_rings_nr);
	if (ret < 0)
		goto fail;
	ret = copy_rings(ctx->scan_rings, ctx->scan_rings_nr,
			 &scan->scan_rings, &scan->scan_rings_nr);
	if (ret < 0)
		goto fail;
	ret = copy_caps(ctx->state_caps, ctx->state_caps_nr,
			&scan->state_caps, &scan->state_caps_nr);
	if (ret < 0)
		goto fail;
	ret = copy_caps(ctx->scan_caps, ctx->scan_caps_nr,
			&scan->scan_caps, &scan->scan_caps_nr);
	if (ret < 0)
		goto fail;
	return 0;
fail:
	rc_scan_free(scan);
	return ret;
}

static int emit_diff(struct rc_diff *out, size_t cap, size_t *nr,
		     __u32 id, __u8 type, __u8 data, __u8 cp)
{
	struct rc_diff *d;

	if (*nr >= cap)
		return -E2BIG;
	d = &out[*nr];
	d->id = id;
	d->type = type;
	d->data = data;
	d->cp = cp;
	(*nr)++;
	return 0;
}

static size_t ring_end(const struct rc_ring *a, size_t n, size_t i)
{
	__u32 id = a[i].id;

	while (i < n && a[i].id == id)
		i++;
	return i;
}

static size_t cap_end(const struct rc_cap *a, size_t n, size_t i)
{
	__u32 id = a[i].id;

	while (i < n && a[i].id == id)
		i++;
	return i;
}

static size_t cap_find(const struct rc_cap *a, size_t n, __u32 id)
{
	size_t lo = 0;
	size_t hi = n;

	while (lo < hi) {
		size_t mid = lo + (hi - lo) / 2;

		if (a[mid].id < id)
			lo = mid + 1;
		else
			hi = mid;
	}
	if (lo < n && a[lo].id == id)
		return lo;
	return n;
}

static int conf_diff(const struct rc_scan *s, struct rc_diff *out,
		     size_t cap, size_t *nr, size_t i, size_t j)
{
	if (s->state_rings[i].state == s->scan_rings[j].state)
		return 0;
	return emit_diff(out, cap, nr, s->state_rings[i].id, RC_CONF,
			 s->scan_rings[j].state, s->state_rings[i].state);
}

static int merge_rings(const struct rc_scan *s, struct rc_diff *out,
		       size_t cap, size_t *nr)
{
	size_t i = 0;
	size_t j = 0;
	int ret;

	while (i < s->state_rings_nr || j < s->scan_rings_nr) {
		if (i >= s->state_rings_nr) {
			ret = emit_diff(out, cap, nr, s->scan_rings[j].id,
					RC_NEW, s->scan_rings[j].state, 0);
			j = ring_end(s->scan_rings, s->scan_rings_nr, j);
		} else if (j >= s->scan_rings_nr) {
			ret = emit_diff(out, cap, nr, s->state_rings[i].id,
					RC_MISS, 0, s->state_rings[i].state);
			i = ring_end(s->state_rings,
				     s->state_rings_nr, i);
		} else if (s->state_rings[i].id == s->scan_rings[j].id) {
			ret = conf_diff(s, out, cap, nr, i, j);
			i = ring_end(s->state_rings,
				     s->state_rings_nr, i);
			j = ring_end(s->scan_rings, s->scan_rings_nr, j);
		} else if (s->state_rings[i].id < s->scan_rings[j].id) {
			ret = emit_diff(out, cap, nr, s->state_rings[i].id,
					RC_MISS, 0, s->state_rings[i].state);
			i = ring_end(s->state_rings,
				     s->state_rings_nr, i);
		} else {
			ret = emit_diff(out, cap, nr, s->scan_rings[j].id,
					RC_NEW, s->scan_rings[j].state, 0);
			j = ring_end(s->scan_rings, s->scan_rings_nr, j);
		}
		if (ret < 0)
			return ret;
	}
	return 0;
}

static int cap_unverified(const struct rc_cap *a, size_t from, size_t end)
{
	size_t k;

	for (k = from; k < end; k++)
		if (a[k].verified == 0)
			return 1;
	return 0;
}

static int cap_revoked(const struct rc_cap *a, size_t from, size_t end)
{
	size_t k;

	for (k = from; k < end; k++)
		if (a[k].state == RC_CAP_REVOKED)
			return 1;
	return 0;
}

static int verify_caps(const struct rc_scan *s, struct rc_diff *out,
		       size_t cap, size_t *nr)
{
	size_t i = 0;

	while (i < s->scan_caps_nr) {
		size_t end = cap_end(s->scan_caps, s->scan_caps_nr, i);
		int ret = 0;

		if (cap_unverified(s->scan_caps, i, end))
			ret = emit_diff(out, cap, nr, s->scan_caps[i].id,
					RC_VERIFY, s->scan_caps[i].state,
					0);
		if (ret < 0)
			return ret;
		i = end;
	}
	return 0;
}

static int revoke_caps(const struct rc_scan *s, struct rc_diff *out,
		       size_t cap, size_t *nr)
{
	size_t i = 0;

	while (i < s->state_caps_nr) {
		size_t end = cap_end(s->state_caps, s->state_caps_nr, i);
		int ret = 0;

		if (cap_revoked(s->state_caps, i, end)) {
			size_t j = cap_find(s->scan_caps,
					    s->scan_caps_nr,
					    s->state_caps[i].id);

			if (j < s->scan_caps_nr &&
			    s->scan_caps[j].state != RC_CAP_REVOKED)
				ret = emit_diff(out, cap, nr,
						s->state_caps[i].id,
						RC_REVOKE,
						s->scan_caps[j].state,
						RC_CAP_REVOKED);
		}
		if (ret < 0)
			return ret;
		i = end;
	}
	return 0;
}

int rc_detect(struct rc_scan *scan, struct rc_diff *out, size_t cap,
	      size_t *nr)
{
	int ret;

	*nr = 0;
	ret = merge_rings(scan, out, cap, nr);
	if (ret < 0)
		return ret;
	ret = verify_caps(scan, out, cap, nr);
	if (ret < 0)
		return ret;
	ret = revoke_caps(scan, out, cap, nr);
	if (ret < 0)
		return ret;
	if (*nr > 1)
		qsort(out, *nr, sizeof(*out), diff_cmp);
	return 0;
}
