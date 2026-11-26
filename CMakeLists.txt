# SPDX-License-Identifier: GPL-2.0-only
#
# security/CMakeLists.txt — security 子仓的用户态构建入口
#
# 职责：构建 Landlock 与 IPC 控制面的用户态
# 库、CLI 与测试。
# security/airy_lsm 内核模块仍由同目录 Kbuild
# 构建，本文件不引用、不改写 Kbuild。
#
# 策略：C11；-Wall -Wextra -Werror；
# _FORTIFY_SOURCE=2；栈保护。
cmake_minimum_required(VERSION 3.20)
project(airymax-security LANGUAGES C)

include(GNUInstallDirs)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
	set(CMAKE_BUILD_TYPE Release CACHE STRING "构建类型" FORCE)
endif()

add_compile_options(-Wall -Wextra -Werror
	-D_FORTIFY_SOURCE=2
	-fstack-protector-strong)
add_compile_definitions(_GNU_SOURCE)

option(BUILD_TESTING "构建并注册用户态测试" ON)
if(BUILD_TESTING)
	enable_testing()
endif()

add_subdirectory(landlock)
add_subdirectory(ipc)
