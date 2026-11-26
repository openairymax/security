// SPDX-License-Identifier: GPL-2.0-only
/*
 * ll_api.h — Landlock 用户态沙箱库的公共接口
 *
 * 职责：
 *   声明策略模型、策略加载/解析、规则集
 *   构建与施加四组接口。本库只做文件系统
 *   访问控制；6.6 基线 ABI 3 不含网络规则，
 *   故不提供任何网络访问位，避免把内核
 *   不支持的能力伪装成可配置项。
 *
 * 策略文本格式见 ll_policy.c 文件头与
 * `airy-landlock --help`。
 *
 * 文档锚点：
 *   docs/docs-linux/110-security/
 *   02-landlock-sandbox.md §7、§8
 */
#ifndef AIRY_LANDLOCK_LL_API_H
#define AIRY_LANDLOCK_LL_API_H

#include <linux/types.h>
#include <stddef.h>

/*
 * 单条策略的规则数上限；超过即判错，
 * 避免策略文件成为无界输入。
 */
#define LL_MAX_RULES	64

/* 文件系统访问位，取值与内核 UAPI 一致（ABI 3）。 */
#define LL_FS_EXECUTE		(1ULL << 0)
#define LL_FS_WRITE_FILE	(1ULL << 1)
#define LL_FS_READ_FILE		(1ULL << 2)
#define LL_FS_READ_DIR		(1ULL << 3)
#define LL_FS_REMOVE_DIR	(1ULL << 4)
#define LL_FS_REMOVE_FILE	(1ULL << 5)
#define LL_FS_MAKE_CHAR		(1ULL << 6)
#define LL_FS_MAKE_DIR		(1ULL << 7)
#define LL_FS_MAKE_REG		(1ULL << 8)
#define LL_FS_MAKE_SOCK		(1ULL << 9)
#define LL_FS_MAKE_FIFO		(1ULL << 10)
#define LL_FS_MAKE_BLOCK	(1ULL << 11)
#define LL_FS_MAKE_SYM		(1ULL << 12)
#define LL_FS_REFER		(1ULL << 13)
#define LL_FS_TRUNCATE		(1ULL << 14)

/*
 * 读集合与写集合；rw 规则请求两者，
 * 再由 handled 裁剪。
 */
#define LL_FS_READ	(LL_FS_READ_FILE | LL_FS_READ_DIR)
#define LL_FS_WRITE	(LL_FS_WRITE_FILE | LL_FS_TRUNCATE | \
			 LL_FS_REMOVE_DIR | LL_FS_REMOVE_FILE | \
			 LL_FS_MAKE_CHAR | LL_FS_MAKE_DIR | \
			 LL_FS_MAKE_REG | LL_FS_MAKE_SOCK | \
			 LL_FS_MAKE_FIFO | LL_FS_MAKE_BLOCK | \
			 LL_FS_MAKE_SYM | LL_FS_REFER)

/*
 * 缺省 handled：只限制写、删、建、改名与
 * 执行，读保持放行。MAKE_CHAR 不在缺省
 * 集合内，设备节点创建仍受内核权限位约束。
 */
#define LL_DFL_HANDLED	(LL_FS_WRITE_FILE | LL_FS_TRUNCATE | \
			 LL_FS_REMOVE_FILE | LL_FS_REMOVE_DIR | \
			 LL_FS_MAKE_REG | LL_FS_MAKE_DIR | \
			 LL_FS_MAKE_SOCK | LL_FS_MAKE_FIFO | \
			 LL_FS_MAKE_BLOCK | LL_FS_MAKE_SYM | \
			 LL_FS_REFER | LL_FS_EXECUTE)

/*
 * 一条路径规则：path 为绝对路径，access
 * 为已按 handled 裁剪的访问位。
 */
struct ll_rule {
	char *path;
	__u64 access;
};

/*
 * 一份策略：规则数组、规则数与 handled
 * 掩码。rules 由库统一分配。
 */
struct ll_policy {
	struct ll_rule *rules;
	size_t nr;
	__u64 handled;
};

/*
 * 查询内核 ABI：>=1 为支持的版本；0 表示
 * 不支持；负值为 -errno。
 */
int ll_sys_abi(void);

/*
 * 读取并解析策略文件。err/len 可为 NULL/0；
 * 成功返回 0，失败返回 -errno，并在 err 中
 * 写入可读原因。pol 必须零初始化，成功后
 * 由调用方用 ll_policy_free 释放。
 */
int ll_policy_load(const char *path, struct ll_policy *pol, char *err,
		   size_t len);

/*
 * 解析 NUL 结尾的策略文本。语义与
 * ll_policy_load 相同；文本非法返回 -EINVAL。
 * pol 必须零初始化。
 */
int ll_policy_parse(const char *text, struct ll_policy *pol, char *err,
		    size_t len);

/*
 * 由策略构建 Landlock 规则集：创建 ruleset
 * 后逐条 add_rule。成功返回规则集 fd（调用
 * 方负责 close），失败返回 -errno 且不泄漏
 * 任何 fd。
 */
int ll_policy_build(const struct ll_policy *pol);

/*
 * 施加策略到当前进程：PR_SET_NO_NEW_PRIVS、
 * 构建规则集、restrict_self。成功返回 0，
 * 失败返回 -errno（-ENOTSUP 表示内核不支持）。
 * 成功后不可逆，调用方通常紧接着 exec。
 */
int ll_policy_apply(const struct ll_policy *pol);

/*
 * 释放策略内全部内存并清零；对同一对象
 * 重复调用是安全的。
 */
void ll_policy_free(struct ll_policy *pol);

#endif /* AIRY_LANDLOCK_LL_API_H */
