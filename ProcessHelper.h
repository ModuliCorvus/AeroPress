#pragma once

#include <windows.h>
#include <QString>

/**
 * @brief 架构类型枚举
 */
enum class Architecture {
    Unknown,
    x86,
    x64,
    ARM64
};

/**
 * @brief 架构信息
 */
struct ArchitectureInfo {
    Architecture arch = Architecture::Unknown;
    QString archString = "unknown";     // "x86", "x64", "arm64", "unknown"
};

/**
 * @brief 进程辅助工具类
 *
 * 提供架构检测、权限检查、注入验证、安全验证等辅助功能。
 * 从 DetoursDllInjector 和 DetoursAdvancedFeatures 迁移而来。
 */
class ProcessHelper
{
public:
    /**
     * @brief 获取文件架构信息（Qt风格）
     */
    static ArchitectureInfo getFileArchitecture(const QString& filePath);

    /**
     * @brief 获取文件架构信息（C风格，避免C++对象析构问题）
     */
    static const char* getFileArchitectureC(const wchar_t* filePath);

    /**
     * @brief 检查目标exe和DLL的架构兼容性
     */
    static bool checkArchitectureCompatibility(const QString& executablePath, const QString& dllPath);

    /**
     * @brief 检查当前进程是否有管理员权限
     */
    static bool hasAdministratorPrivileges();

    /**
     * @brief 验证DLL是否成功加载到目标进程
     */
    static bool verifyInjection(DWORD processId, const QString& dllPath);

    /**
     * @brief 获取详细架构信息（通过PE文件读取）
     */
    static ArchitectureInfo getDetailedArchitecture(const QString& executablePath);

    /**
     * @brief 验证DLL数字签名
     */
    static bool verifyDllSignature(const QString& dllPath);

    /**
     * @brief 验证DLL完整性
     */
    static bool verifyDllIntegrity(const QString& dllPath);
};
