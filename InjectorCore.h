#pragma once

#include <windows.h>
#include <QString>
#include <QStringList>

/**
 * @brief 注入方法枚举
 */
enum class InjectionMethod {
    CreateProcessWithDll,    // 创建进程时注入（默认，推荐）
    UpdateRunningProcess,    // 注入到运行中的进程
    HelperProcess            // 通过Helper进程注入
};

/**
 * @brief 注入配置
 */
struct InjectionConfig {
    QString targetExecutable;           // 目标可执行文件路径
    QString workingDirectory;           // 工作目录（默认为exe所在目录）
    QStringList arguments;              // 传递给目标进程的参数
    QStringList dllPaths;               // 要注入的DLL路径列表
    InjectionMethod method = InjectionMethod::CreateProcessWithDll;
    bool suspendAfterCreation = false;  // 创建后是否挂起进程
    bool waitForInjection = false;      // 是否等待并验证注入
    int timeoutSeconds = 30;            // 超时时间
    bool enableDebugOutput = false;     // 是否启用调试输出
    DWORD targetPid = 0;               // 目标进程PID（用于update/helper方法）
};

/**
 * @brief 注入结果
 */
struct InjectionResult {
    bool success = false;               // 是否成功
    int exitCode = 0;                   // 退出码
    DWORD processId = 0;               // 创建的进程ID
    DWORD threadId = 0;                // 创建的主线程ID
    QString method;                     // 使用的注入方法
    QString message;                    // 结果消息
    QString error;                      // 错误信息（失败时）
    QString details;                    // 详细信息（失败时）
    QStringList injectedDlls;           // 成功注入的DLL列表
};

/**
 * @brief 注入核心逻辑类
 *
 * 封装 Detours API 调用，提供三种注入方法：
 * - CreateProcessWithDll: 创建进程时注入
 * - UpdateRunningProcess: 注入到运行中的进程
 * - HelperProcess: 通过Helper进程注入
 */
class InjectorCore
{
public:
    InjectorCore();
    ~InjectorCore();

    /**
     * @brief 启动进程并注入DLL
     */
    InjectionResult createProcessWithDll(const InjectionConfig& config);

    /**
     * @brief 向运行中的进程注入DLL
     */
    InjectionResult updateRunningProcess(const InjectionConfig& config);

    /**
     * @brief 通过Helper进程注入DLL
     */
    InjectionResult injectViaHelper(const InjectionConfig& config);

private:
    std::vector<std::string> prepareDllPaths(const QStringList& dllPaths);
    QString getWindowsErrorString(DWORD errorCode);

    PROCESS_INFORMATION m_processInfo;
    bool m_processCreated = false;
};
