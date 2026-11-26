# SPDX-License-Identifier: GPL-2.0-only
#
# security/landlock/CMakeLists.txt —
# Landlock 用户态库、CLI 与测试
#
# 产物：静态库 ll、可执行 airy-landlock、
# 测试 ll_test；安装 CLI 到 bin，
# 出厂策略到 share/airymax/landlock/agent.conf。
add_library(ll STATIC
	ll_sys.c
	ll_policy.c)
target_include_directories(ll PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(airy-landlock ll_main.c)
target_link_libraries(airy-landlock PRIVATE ll)

install(TARGETS airy-landlock RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES policies/agent.conf
	DESTINATION ${CMAKE_INSTALL_DATADIR}/airymax/landlock)

if(BUILD_TESTING)
	add_executable(ll_test tests/ll_test.c)
	target_link_libraries(ll_test PRIVATE ll)
	add_test(NAME ll_test COMMAND ll_test)
endif()
