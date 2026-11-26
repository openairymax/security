# SPDX-License-Identifier: GPL-2.0-only
#
# security/ipc/CMakeLists.txt —
# IPC 控制面 Reconciliation 库、CLI 与测试
#
# 产物：静态库 rc、可执行 airy-reconcile、
# 测试 rc_test；安装 CLI 到 sbin。
add_library(rc STATIC
	rc_diff.c
	rc_plan.c
	rc_loop.c)
target_include_directories(rc PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(airy-reconcile rc_main.c)
target_link_libraries(airy-reconcile PRIVATE rc)

install(TARGETS airy-reconcile RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR})

if(BUILD_TESTING)
	add_executable(rc_test tests/rc_test.c)
	target_link_libraries(rc_test PRIVATE rc)
	add_test(NAME rc_test COMMAND rc_test)
endif()
