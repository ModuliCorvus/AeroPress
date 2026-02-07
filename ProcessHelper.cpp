#include "ProcessHelper.h"
#include <QFileInfo>
#include <QFile>
#include <QDebug>
#include <tlhelp32.h>
#include <psapi.h>
#include <wintrust.h>
#include <softpub.h>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

// T011: C风格的架构检测函数，避免C++对象析构问题
const char* ProcessHelper::getFileArchitectureC(const wchar_t* filePath)
{
    HANDLE fileHandle = CreateFileW(
        filePath,
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (fileHandle == INVALID_HANDLE_VALUE) {
        return "unknown";
    }

    HANDLE mappingHandle = CreateFileMappingW(fileHandle, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!mappingHandle) {
        CloseHandle(fileHandle);
        return "unknown";
    }

    LPVOID baseAddress = MapViewOfFile(mappingHandle, FILE_MAP_READ, 0, 0, 0);
    if (!baseAddress) {
        CloseHandle(mappingHandle);
        CloseHandle(fileHandle);
        return "unknown";
    }

    const char* architectureResult = "unknown";

    __try {
        PIMAGE_DOS_HEADER dosHeader = static_cast<PIMAGE_DOS_HEADER>(baseAddress);
        if (dosHeader->e_magic == IMAGE_DOS_SIGNATURE) {
            PIMAGE_NT_HEADERS ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
                static_cast<BYTE*>(baseAddress) + dosHeader->e_lfanew);

            if (ntHeaders->Signature == IMAGE_NT_SIGNATURE) {
                switch (ntHeaders->FileHeader.Machine) {
                case IMAGE_FILE_MACHINE_I386:
                    architectureResult = "x86";
                    break;
                case IMAGE_FILE_MACHINE_AMD64:
                    architectureResult = "x64";
                    break;
                case IMAGE_FILE_MACHINE_ARM64:
                    architectureResult = "arm64";
                    break;
                default:
                    architectureResult = "unknown";
                    break;
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        architectureResult = "unknown";
    }

    UnmapViewOfFile(baseAddress);
    CloseHandle(mappingHandle);
    CloseHandle(fileHandle);

    return architectureResult;
}

// T011: Qt风格的架构检测
ArchitectureInfo ProcessHelper::getFileArchitecture(const QString& filePath)
{
    ArchitectureInfo info;
    std::wstring wFilePath = filePath.toStdWString();
    const char* result = getFileArchitectureC(wFilePath.c_str());
    info.archString = QString(result);

    if (info.archString == "x86") {
        info.arch = Architecture::x86;
    } else if (info.archString == "x64") {
        info.arch = Architecture::x64;
    } else if (info.archString == "arm64") {
        info.arch = Architecture::ARM64;
    } else {
        info.arch = Architecture::Unknown;
    }

    return info;
}

// T012: 检查目标exe和DLL的架构兼容性
bool ProcessHelper::checkArchitectureCompatibility(const QString& executablePath, const QString& dllPath)
{
    ArchitectureInfo exeArch = getFileArchitecture(executablePath);
    ArchitectureInfo dllArch = getFileArchitecture(dllPath);

    if (exeArch.arch == Architecture::Unknown || dllArch.arch == Architecture::Unknown) {
        qDebug() << "Warning: Unable to determine architecture for" << executablePath << "or" << dllPath;
        return true; // 假设兼容
    }

    return exeArch.arch == dllArch.arch;
}

// T013: 检查当前进程是否有管理员权限
bool ProcessHelper::hasAdministratorPrivileges()
{
    BOOL isAdmin = FALSE;
    PSID adminGroup = nullptr;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;

    if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(nullptr, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }

    return isAdmin == TRUE;
}

// T014: 验证DLL是否成功加载到目标进程
bool ProcessHelper::verifyInjection(DWORD processId, const QString& dllPath)
{
    QFileInfo dllInfo(dllPath);
    QString dllName = dllInfo.fileName();

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);
    if (snapshot == INVALID_HANDLE_VALUE) {
        qDebug() << "Failed to create module snapshot for process" << processId
                 << "Error:" << GetLastError();
        return false;
    }

    MODULEENTRY32W moduleEntry;
    moduleEntry.dwSize = sizeof(MODULEENTRY32W);

    bool found = false;
    if (Module32FirstW(snapshot, &moduleEntry)) {
        do {
            QString moduleName = QString::fromWCharArray(moduleEntry.szModule);
            if (moduleName.compare(dllName, Qt::CaseInsensitive) == 0) {
                found = true;
                break;
            }
        } while (Module32NextW(snapshot, &moduleEntry));
    }

    CloseHandle(snapshot);
    return found;
}

// T015: 获取详细架构信息（通过PE文件读取）
ArchitectureInfo ProcessHelper::getDetailedArchitecture(const QString& executablePath)
{
    ArchitectureInfo info;

    QFile file(executablePath);
    if (!file.open(QIODevice::ReadOnly)) {
        return info;
    }

    // 读取PE头
    QByteArray dosHeader = file.read(64);
    if (dosHeader.size() < 64 || dosHeader[0] != 'M' || dosHeader[1] != 'Z') {
        return info;
    }

    // 获取PE头偏移
    DWORD peOffset = *reinterpret_cast<const DWORD*>(dosHeader.data() + 60);
    file.seek(peOffset);

    QByteArray peHeader = file.read(24);
    if (peHeader.size() < 24 || peHeader[0] != 'P' || peHeader[1] != 'E') {
        return info;
    }

    // 获取机器类型
    WORD machine = *reinterpret_cast<const WORD*>(peHeader.data() + 4);

    switch (machine) {
    case 0x014c: // IMAGE_FILE_MACHINE_I386
        info.arch = Architecture::x86;
        info.archString = "x86";
        break;
    case 0x8664: // IMAGE_FILE_MACHINE_AMD64
        info.arch = Architecture::x64;
        info.archString = "x64";
        break;
    case 0xAA64: // IMAGE_FILE_MACHINE_ARM64
        info.arch = Architecture::ARM64;
        info.archString = "arm64";
        break;
    default:
        info.arch = Architecture::Unknown;
        info.archString = "unknown";
        break;
    }

    return info;
}

// T016: 验证DLL数字签名
bool ProcessHelper::verifyDllSignature(const QString& dllPath)
{
    std::wstring wPath = dllPath.toStdWString();

    WINTRUST_FILE_INFO fileData = {};
    fileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileData.pcwszFilePath = wPath.c_str();
    fileData.hFile = nullptr;
    fileData.pgKnownSubject = nullptr;

    WINTRUST_DATA winTrustData = {};
    winTrustData.cbStruct = sizeof(WINTRUST_DATA);
    winTrustData.pPolicyCallbackData = nullptr;
    winTrustData.pSIPClientData = nullptr;
    winTrustData.dwUIChoice = WTD_UI_NONE;
    winTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
    winTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
    winTrustData.hWVTStateData = nullptr;
    winTrustData.pwszURLReference = nullptr;
    winTrustData.dwProvFlags = WTD_SAFER_FLAG;
    winTrustData.pFile = &fileData;

    GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    LONG result = WinVerifyTrust(nullptr, &policyGUID, &winTrustData);

    // 清理
    winTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &policyGUID, &winTrustData);

    return result == ERROR_SUCCESS;
}

// T016: 验证DLL完整性
bool ProcessHelper::verifyDllIntegrity(const QString& dllPath)
{
    QFileInfo fileInfo(dllPath);
    if (!fileInfo.exists()) {
        return false;
    }

    QFile file(dllPath);
    if (!file.open(QIODevice::ReadOnly)) {
        return false;
    }

    // 检查PE头
    QByteArray header = file.read(64);
    if (header.size() < 64) {
        return false;
    }

    // 检查DOS头签名
    if (header[0] != 'M' || header[1] != 'Z') {
        return false;
    }

    // 基本完整性检查通过
    return true;
}
