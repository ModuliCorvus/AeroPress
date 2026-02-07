#include "InjectorCore.h"
#include "ProcessHelper.h"
#include <QFileInfo>
#include <QThread>
#include <QDebug>
#include <detours.h>
#include <tlhelp32.h>
#include <psapi.h>

InjectorCore::InjectorCore()
{
    ZeroMemory(&m_processInfo, sizeof(m_processInfo));
}

InjectorCore::~InjectorCore()
{
    if (m_processCreated) {
        if (m_processInfo.hProcess) {
            CloseHandle(m_processInfo.hProcess);
        }
        if (m_processInfo.hThread) {
            CloseHandle(m_processInfo.hThread);
        }
    }
}

InjectionResult InjectorCore::createProcessWithDll(const InjectionConfig& config)
{
    InjectionResult result;
    result.method = "create";

    // 架构兼容性检查
    for (const QString& dllPath : config.dllPaths) {
        if (!ProcessHelper::checkArchitectureCompatibility(config.targetExecutable, dllPath)) {
            ArchitectureInfo exeArch = ProcessHelper::getFileArchitecture(config.targetExecutable);
            ArchitectureInfo dllArch = ProcessHelper::getFileArchitecture(dllPath);
            result.success = false;
            result.exitCode = 4;
            result.error = "Architecture mismatch";
            result.details = QString("Target executable is %1 but DLL '%2' is %3")
                .arg(exeArch.archString)
                .arg(QFileInfo(dllPath).fileName())
                .arg(dllArch.archString);
            return result;
        }
    }

    // 准备DLL路径数组
    auto dllPathsVector = prepareDllPaths(config.dllPaths);
    std::vector<LPCSTR> dllPathsArray;
    for (const auto& path : dllPathsVector) {
        dllPathsArray.push_back(path.c_str());
    }

    // 准备启动信息
    STARTUPINFOW startupInfo;
    ZeroMemory(&startupInfo, sizeof(startupInfo));
    startupInfo.cb = sizeof(startupInfo);

    // 准备命令行
    QString commandLine = config.targetExecutable;
    if (!config.arguments.isEmpty()) {
        commandLine += " " + config.arguments.join(" ");
    }

    // 准备工作目录
    QString workDir = config.workingDirectory;
    if (workDir.isEmpty()) {
        workDir = QFileInfo(config.targetExecutable).absolutePath();
    }

    // 转换为 wchar_t*
    std::wstring wCommandLine = commandLine.toStdWString();
    std::wstring wWorkDir = workDir.toStdWString();
    std::wstring wTargetExe = config.targetExecutable.toStdWString();

    DWORD creationFlags = config.suspendAfterCreation ? CREATE_SUSPENDED : 0;

    BOOL bResult = FALSE;

    if (config.dllPaths.size() == 1) {
        // 单个DLL注入
        std::string dllPathAnsi = config.dllPaths.first().toLocal8Bit().toStdString();
        bResult = DetourCreateProcessWithDllW(
            wTargetExe.c_str(),
            &wCommandLine[0],
            nullptr,
            nullptr,
            FALSE,
            creationFlags,
            nullptr,
            wWorkDir.c_str(),
            &startupInfo,
            &m_processInfo,
            dllPathAnsi.c_str(),
            nullptr
        );
    } else {
        // 多个DLL注入
        bResult = DetourCreateProcessWithDllsW(
            wTargetExe.c_str(),
            &wCommandLine[0],
            nullptr,
            nullptr,
            FALSE,
            creationFlags,
            nullptr,
            wWorkDir.c_str(),
            &startupInfo,
            &m_processInfo,
            static_cast<DWORD>(dllPathsArray.size()),
            dllPathsArray.data(),
            nullptr
        );
    }

    if (!bResult) {
        DWORD error = GetLastError();
        QString errorMsg = getWindowsErrorString(error);

        result.success = false;
        result.details = QString("Windows error %1: %2").arg(error).arg(errorMsg);

        if (error == ERROR_ACCESS_DENIED) {
            result.exitCode = 7;
            result.error = "Access denied. Administrator privileges may be required.";
        } else if (error == ERROR_DYNAMIC_CODE_BLOCKED) {
            result.exitCode = 5;
            result.error = "Dynamic code generation is blocked by security policy.";
        } else {
            result.exitCode = 5;
            result.error = QString("Failed to create process with DLL: %1").arg(errorMsg);
        }
        return result;
    }

    m_processCreated = true;

    // 如果需要等待注入完成并验证
    if (config.waitForInjection) {
        QThread::msleep(1000);

        bool allInjected = true;
        for (const QString& dllPath : config.dllPaths) {
            if (!ProcessHelper::verifyInjection(m_processInfo.dwProcessId, dllPath)) {
                allInjected = false;
                break;
            }
        }

        if (!allInjected) {
            result.success = false;
            result.exitCode = 8;
            result.error = "DLL injection verification failed";
            result.processId = m_processInfo.dwProcessId;
            result.threadId = m_processInfo.dwThreadId;
            return result;
        }
    }

    // 成功
    result.success = true;
    result.exitCode = 0;
    result.processId = m_processInfo.dwProcessId;
    result.threadId = m_processInfo.dwThreadId;
    result.injectedDlls = config.dllPaths;
    result.message = "Process created and DLL injected successfully";
    return result;
}

InjectionResult InjectorCore::updateRunningProcess(const InjectionConfig& config)
{
    InjectionResult result;
    result.method = "update";

    if (config.targetPid == 0) {
        result.success = false;
        result.exitCode = 1;
        result.error = "Target process PID is required";
        return result;
    }

    // 架构兼容性检查（如果有目标exe路径）
    if (!config.targetExecutable.isEmpty()) {
        for (const QString& dllPath : config.dllPaths) {
            if (!ProcessHelper::checkArchitectureCompatibility(config.targetExecutable, dllPath)) {
                ArchitectureInfo exeArch = ProcessHelper::getFileArchitecture(config.targetExecutable);
                ArchitectureInfo dllArch = ProcessHelper::getFileArchitecture(dllPath);
                result.success = false;
                result.exitCode = 4;
                result.error = "Architecture mismatch";
                result.details = QString("Target executable is %1 but DLL '%2' is %3")
                    .arg(exeArch.archString)
                    .arg(QFileInfo(dllPath).fileName())
                    .arg(dllArch.archString);
                return result;
            }
        }
    }

    // 检查权限
    if (!ProcessHelper::hasAdministratorPrivileges()) {
        result.success = false;
        result.exitCode = 7;
        result.error = "Administrator privileges required for updating running process";
        return result;
    }

    // 打开目标进程
    HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, config.targetPid);
    if (!processHandle) {
        DWORD error = GetLastError();
        result.success = false;
        if (error == ERROR_ACCESS_DENIED) {
            result.exitCode = 7;
            result.error = "Access denied to target process";
        } else {
            result.exitCode = 5;
            result.error = QString("Failed to open process %1 (Error: %2)").arg(config.targetPid).arg(error);
        }
        return result;
    }

    // 准备DLL路径数组
    auto dllPathsVector = prepareDllPaths(config.dllPaths);
    std::vector<LPCSTR> dllPathsArray;
    for (const auto& path : dllPathsVector) {
        dllPathsArray.push_back(path.c_str());
    }

    // 使用 DetourUpdateProcessWithDll
    BOOL bResult = DetourUpdateProcessWithDll(
        processHandle,
        dllPathsArray.data(),
        static_cast<DWORD>(dllPathsArray.size())
    );

    CloseHandle(processHandle);

    if (!bResult) {
        DWORD error = GetLastError();
        result.success = false;
        result.exitCode = 6;
        result.error = QString("Failed to update process with DLL (Error: %1)").arg(error);
        return result;
    }

    // 验证注入（如果需要）
    if (config.waitForInjection) {
        QThread::msleep(1000);
        for (const QString& dllPath : config.dllPaths) {
            if (!ProcessHelper::verifyInjection(config.targetPid, dllPath)) {
                result.success = false;
                result.exitCode = 8;
                result.error = "DLL injection verification failed";
                return result;
            }
        }
    }

    result.success = true;
    result.exitCode = 0;
    result.processId = config.targetPid;
    result.injectedDlls = config.dllPaths;
    result.message = "Process updated with DLL injection successfully";
    return result;
}

InjectionResult InjectorCore::injectViaHelper(const InjectionConfig& config)
{
    InjectionResult result;
    result.method = "helper";

    if (config.targetPid == 0) {
        result.success = false;
        result.exitCode = 1;
        result.error = "Target process PID is required";
        return result;
    }

    if (config.dllPaths.isEmpty()) {
        result.success = false;
        result.exitCode = 1;
        result.error = "No DLL paths specified";
        return result;
    }

    std::string dllPathAnsi = config.dllPaths.first().toLocal8Bit().toStdString();

    BOOL bResult = DetourProcessViaHelperW(
        config.targetPid,
        dllPathAnsi.c_str(),
        nullptr
    );

    if (!bResult) {
        DWORD error = GetLastError();
        result.success = false;
        result.exitCode = 6;
        result.error = QString("Failed to inject via helper process (Error: %1)").arg(error);
        return result;
    }

    // 验证注入（如果需要）
    if (config.waitForInjection) {
        QThread::msleep(1000);
        for (const QString& dllPath : config.dllPaths) {
            if (!ProcessHelper::verifyInjection(config.targetPid, dllPath)) {
                result.success = false;
                result.exitCode = 8;
                result.error = "DLL injection verification failed";
                return result;
            }
        }
    }

    result.success = true;
    result.exitCode = 0;
    result.processId = config.targetPid;
    result.injectedDlls = config.dllPaths;
    result.message = "DLL injected successfully via helper process";
    return result;
}

std::vector<std::string> InjectorCore::prepareDllPaths(const QStringList& dllPaths)
{
    std::vector<std::string> result;
    for (const QString& path : dllPaths) {
        QFileInfo info(path);
        result.push_back(info.absoluteFilePath().toLocal8Bit().toStdString());
    }
    return result;
}

QString InjectorCore::getWindowsErrorString(DWORD errorCode)
{
    LPWSTR messageBuffer = nullptr;
    DWORD size = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        errorCode,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<LPWSTR>(&messageBuffer),
        0,
        nullptr
    );

    QString message;
    if (size > 0 && messageBuffer) {
        message = QString::fromWCharArray(messageBuffer, size).trimmed();
        LocalFree(messageBuffer);
    } else {
        message = QString("Unknown error (Code: %1)").arg(errorCode);
    }

    return message;
}
