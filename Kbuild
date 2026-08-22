# SPDX-License-Identifier: GPL-2.0-only
#
# agent-linux (AirymaxOS) security submodule Kbuild
# 构建入口：纯 C LSM 独立内核模块（airy_ind）
# 决策 F1：最小可编译骨架（非桩）
#
# 构建命令：
#   make -C /lib/modules/$(uname -r)/build M=$(pwd) modules
#
# 注意：本子仓的 LSM 名为 airy_ind（[IND] 独立层实例），
#       与 kernel 子仓内建的 DEFINE_LSM(airy)（[SS] 同源层）区分。

obj-m := airy_lsm/
