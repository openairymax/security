// SPDX-License-Identifier: GPL-2.0-only
/*
 * ll_sys.c — Landlock syscall 封装与规则集构建
 *
 * 职责：
 *   1. 用 syscall(2) 直接调用
 *      landlock_create_ruleset / add_rule /
 *      restrict_self，不依赖 liblandlock；
 *   2. 对没有 SYS_landlock_* 宏的旧头文件
 *      回退到 __NR_landlock_* 或 x86_64 /
 *      asm-generic 的 444~446；
 *   3. 以 size=0、attr=NULL、VERSION 标志
 *      查询 ABI；
 *   4. 构建规则集时逐条打开 O_PATH fd，任一
 *      add_rule 失败即关闭规则集与 O_PATH fd，
 *      保证不泄漏。
 *
 * 本文件只使用 LL_FS_* 访问位，自带内核结构
 * 布局并用静态断言锁定，因此宿主缺少新版
 * <linux/landlock.h> 时仍可编译。
 *
 * 文档锚点：
 *   docs/docs-linux/110-security/
 *   02-landlock-sandbox.md §7、§8
 */
#include "ll_api.h"

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef SYS_landlock_create_ruleset
#ifdef __NR_landlock_create_ruleset
#define SYS_landlock_create_ruleset	__NR_landlock_create_ruleset
#else
#define SYS_landlock_create_ruleset	444
#endif
#endif

#ifndef SYS_landlock_add_rule
#ifdef __NR_landlock_add_rule
#define SYS_landlock_add_rule		__NR_landlock_add_rule
#else
#define SYS_landlock_add_rule		445
#endif
#endif

#ifndef SYS_landlock_restrict_self
#ifdef __NR_landlock_restrict_self
#define SYS_landlock_restrict_self	__NR_landlock_restrict_self
#else
#define SYS_landlock_restrict_self	446
#endif
#endif

#ifndef LANDLOCK_CREATE_RULESET_VERSION
#define LANDLOCK_CREATE_RULESET_VERSION	(1U << 0)
#endif

#ifndef LANDLOCK_RULE_PATH_BENEATH
#define LANDLOCK_RULE_PATH_BENEATH	1
#endif

/*
 * 规则集属性：ABI 3 只有 handled_access_fs
 * 一个 64 位字段。
 */
struct ll_ruleset_attr {
	__u64 handled_access_fs;
};

/*
 * path_beneath 属性与内核 UAPI 同布局：
 * u64 + s32，按 1 字节对齐。
 */
struct ll_beneath_attr {
	__u64 allowed_access;
	__s32 parent_fd;
} __attribute__((packed));

_Static_assert(sizeof(struct ll_ruleset_attr) == 8,
	       "ruleset attr 布局与内核 UAPI 不一致");
_Static_assert(sizeof(struct ll_beneath_attr) == 12,
	       "path_beneath attr 布局与内核 UAPI 不一致");

int ll_sys_abi(void)
{
	long abi;

	abi = syscall(SYS_landlock_create_ruleset, NULL, 0,
		      LANDLOCK_CREATE_RULESET_VERSION);
	if (abi > 0)
		return (int)abi;
	if (abi == 0)
		return 0;
	if (errno == ENOSYS || errno == EOPNOTSUPP)
		return 0;
	return -errno;
}

/*
 * 校验策略结构：handled 非零、规则数受限、
 * 路径为绝对路径、访问位是 handled 的子集。
 * 解析器已保证这些条件，这里是构建入口的
 * 独立防线。
 */
static int pol_valid(const struct ll_policy *pol)
{
	size_t i;

	if (pol == NULL || pol->handled == 0 || pol->nr > LL_MAX_RULES)
		return 0;
	for (i = 0; i < pol->nr; i++) {
		const struct ll_rule *rule = &pol->rules[i];

		if (rule->path == NULL || rule->path[0] != '/')
			return 0;
		if (rule->access == 0 ||
		    (rule->access & ~pol->handled) != 0)
			return 0;
	}
	return 1;
}

/*
 * 为单条规则打开 O_PATH fd 并 add_rule；
 * 无论成败都关闭该 fd。
 */
static int add_one(int ruleset, const struct ll_rule *rule)
{
	struct ll_beneath_attr attr;
	int pfd, ret = 0;

	pfd = open(rule->path, O_PATH | O_CLOEXEC);
	if (pfd < 0)
		return -errno;
	attr.allowed_access = rule->access;
	attr.parent_fd = pfd;
	if (syscall(SYS_landlock_add_rule, ruleset,
		    LANDLOCK_RULE_PATH_BENEATH, &attr, 0) < 0)
		ret = -errno;
	close(pfd);
	return ret;
}

/*
 * 访问位与内核 ABI 的对应关系：refer 自 ABI 2
 * 起可用，truncate 自 ABI 3 起可用。基线 6.6
 * 为 ABI 3，低版本内核必须显式拒绝而不是让
 * create_ruleset 返回含义模糊的 EINVAL。
 */
static int abi_ok(__u64 hdl, int abi)
{
	if ((hdl & LL_FS_REFER) && abi < 2)
		return 0;
	if ((hdl & LL_FS_TRUNCATE) && abi < 3)
		return 0;
	return 1;
}

int ll_policy_build(const struct ll_policy *pol)
{
	struct ll_ruleset_attr attr;
	int abi, fd, ret;
	size_t i;

	if (!pol_valid(pol))
		return -EINVAL;
	abi = ll_sys_abi();
	if (abi <= 0)
		return abi < 0 ? abi : -ENOTSUP;
	if (!abi_ok(pol->handled, abi))
		return -ENOTSUP;
	attr.handled_access_fs = pol->handled;
	fd = (int)syscall(SYS_landlock_create_ruleset, &attr,
			  sizeof(attr), 0);
	if (fd < 0)
		return -errno;
	for (i = 0; i < pol->nr; i++) {
		ret = add_one(fd, &pol->rules[i]);
		if (ret < 0) {
			close(fd);
			return ret;
		}
	}
	return fd;
}

int ll_policy_apply(const struct ll_policy *pol)
{
	int abi, fd, ret = 0;

	abi = ll_sys_abi();
	if (abi <= 0)
		return abi < 0 ? abi : -ENOTSUP;
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
		return -errno;
	fd = ll_policy_build(pol);
	if (fd < 0)
		return fd;
	if (syscall(SYS_landlock_restrict_self, fd, 0) < 0)
		ret = -errno;
	close(fd);
	return ret;
}
