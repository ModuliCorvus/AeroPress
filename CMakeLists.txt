project(AeroPress LANGUAGES CXX)

# AeroPress - DLL注入独立可执行程序
# 内置 Detours 4.0.1 静态库，动态链接 Qt Core

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Qt6 REQUIRED COMPONENTS Core)

# 源文件
set(AEROPRESS_SOURCES
    main.cpp
    InjectorCore.h
    InjectorCore.cpp
    ProcessHelper.h
    ProcessHelper.cpp
)

add_executable(AeroPress ${AEROPRESS_SOURCES})

# 内置 Detours 静态库路径
set(AEROPRESS_DETOURS_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/detours")
set(AEROPRESS_DETOURS_INCLUDE "${AEROPRESS_DETOURS_ROOT}/include")

# 根据构建类型选择 Detours 库
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(AEROPRESS_DETOURS_LIB "${AEROPRESS_DETOURS_ROOT}/lib/Debug/detours.lib")
else()
    set(AEROPRESS_DETOURS_LIB "${AEROPRESS_DETOURS_ROOT}/lib/Release/detours.lib")
endif()

# 链接库
target_link_libraries(AeroPress
    PRIVATE
        Qt6::Core
        ${AEROPRESS_DETOURS_LIB}
        kernel32
        user32
        advapi32
        psapi
        wintrust
        crypt32
)

# 包含目录
target_include_directories(AeroPress
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${AEROPRESS_DETOURS_INCLUDE}
)

# Windows UAC manifest - 要求管理员权限
if(WIN32 AND MSVC)
    set_target_properties(AeroPress PROPERTIES
        LINK_FLAGS "/MANIFESTUAC:\"level='requireAdministrator' uiAccess='false'\""
    )
endif()

# POST_BUILD: 复制到主程序输出目录
add_custom_command(TARGET AeroPress POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        $<TARGET_FILE:AeroPress>
        ${CMAKE_BINARY_DIR}/src/$<TARGET_FILE_NAME:AeroPress>
    COMMENT "Copying AeroPress.exe to main application directory..."
)

# 测试
if (TESTING)
    add_subdirectory(test)
endif()
