#include "InjectorCore.h"
#include "ProcessHelper.h"

#include <QCoreApplication>
#include <QCommandLineParser>
#include <QCommandLineOption>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QFileInfo>
#include <QDir>
#include <QTextStream>

#include <cstdio>

/**
 * @brief 退出码枚举
 */
enum ExitCode {
    Success = 0,
    InvalidArguments = 1,
    TargetNotFound = 2,
    DllNotFound = 3,
    ArchitectureMismatch = 4,
    ProcessCreationFailed = 5,
    InjectionFailed = 6,
    AccessDenied = 7,
    VerificationFailed = 8,
    Timeout = 9,
    UnknownError = 10
};

// 全局标志
static bool g_jsonOutput = false;
static bool g_debugOutput = false;
static QString g_resultFile;

/**
 * @brief 输出调试信息到 stderr
 */
static void debugLog(const QString& message)
{
    if (g_debugOutput) {
        fprintf(stderr, "[AeroPress] %s\n", message.toLocal8Bit().constData());
    }
}

/**
 * @brief 将 JSON 数据写入结果文件（如果指定了 --result-file）
 */
static void writeResultFile(const QByteArray& jsonData)
{
    if (g_resultFile.isEmpty()) {
        return;
    }
    QFile file(g_resultFile);
    if (file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        file.write(jsonData);
        file.close();
        debugLog("Result written to file: " + g_resultFile);
    } else {
        debugLog("Failed to write result file: " + g_resultFile);
    }
}

static void outputJsonSuccess(const InjectionResult& result)
{
    QJsonObject json;
    json["success"] = true;
    json["exitCode"] = 0;
    json["processId"] = static_cast<qint64>(result.processId);
    json["threadId"] = static_cast<qint64>(result.threadId);
    json["method"] = result.method;

    QJsonArray dlls;
    for (const QString& dll : result.injectedDlls) {
        dlls.append(dll);
    }
    json["injectedDlls"] = dlls;
    json["message"] = result.message;

    QJsonDocument doc(json);
    QByteArray jsonData = doc.toJson(QJsonDocument::Compact);
    fprintf(stdout, "%s\n", jsonData.constData());
    writeResultFile(jsonData);
}

/**
 * @brief 输出 JSON 失败结果到 stdout
 */
static void outputJsonError(int exitCode, const QString& error, const QString& details = QString())
{
    QJsonObject json;
    json["success"] = false;
    json["exitCode"] = exitCode;
    json["error"] = error;
    if (!details.isEmpty()) {
        json["details"] = details;
    }

    QJsonDocument doc(json);
    QByteArray jsonData = doc.toJson(QJsonDocument::Compact);
    fprintf(stdout, "%s\n", jsonData.constData());
    writeResultFile(jsonData);
}

/**
 * @brief 输出错误信息（根据 --json 标志选择格式）
 */
static int reportError(int exitCode, const QString& error, const QString& details = QString())
{
    if (g_jsonOutput) {
        outputJsonError(exitCode, error, details);
    } else {
        fprintf(stderr, "Error: %s\n", error.toLocal8Bit().constData());
        if (!details.isEmpty()) {
            fprintf(stderr, "Details: %s\n", details.toLocal8Bit().constData());
        }
    }
    return exitCode;
}

/**
 * @brief 输出帮助信息
 */
static void printHelp()
{
    fprintf(stdout,
        "AeroPress - DLL Injection Tool\n"
        "\n"
        "Usage: AeroPress.exe --exe <target.exe> --dll <dll_path> [options]\n"
        "\n"
        "Required arguments:\n"
        "  --exe <path>          Target executable file path\n"
        "  --dll <path>          DLL path to inject (can be specified multiple times)\n"
        "\n"
        "Optional arguments:\n"
        "  --work-dir <path>     Working directory (default: exe directory)\n"
        "  --args <arguments>    Arguments to pass to target process\n"
        "  --method <method>     Injection method: create (default) | update | helper\n"
        "  --timeout <seconds>   Timeout in seconds (default: 30)\n"
        "  --pid <pid>           Target process PID (for update/helper method)\n"
        "  --suspend             Suspend process after creation\n"
        "  --verify              Verify DLL injection after completion\n"
        "  --debug               Enable debug output to stderr\n"
        "  --json                Output results in JSON format\n"
        "  --result-file <path>  Write JSON result to file (for UAC elevation)\n"
        "  --help                Show this help message\n"
        "\n"
        "Exit codes:\n"
        "  0   Success\n"
        "  1   Invalid arguments\n"
        "  2   Target file not found\n"
        "  3   DLL file not found\n"
        "  4   Architecture mismatch\n"
        "  5   Process creation failed\n"
        "  6   Injection failed\n"
        "  7   Access denied / insufficient privileges\n"
        "  8   Verification failed\n"
        "  9   Timeout\n"
        "  10  Unknown error\n"
        "\n"
        "Examples:\n"
        "  AeroPress.exe --exe \"C:/Game/Game.exe\" --dll \"C:/path/d3d11.dll\" --json\n"
        "  AeroPress.exe --method update --pid 12345 --dll \"C:/path/d3d11.dll\" --json\n"
        "  AeroPress.exe --exe \"C:/Game/Game.exe\" --dll \"C:/d3d11.dll\" --dll \"C:/d3dcompiler_47.dll\" --json\n"
    );
}

/**
 * @brief 解析注入方法字符串
 */
static InjectionMethod parseMethod(const QString& methodStr)
{
    if (methodStr == "update") {
        return InjectionMethod::UpdateRunningProcess;
    } else if (methodStr == "helper") {
        return InjectionMethod::HelperProcess;
    }
    return InjectionMethod::CreateProcessWithDll;
}

/**
 * @brief 方法枚举转字符串
 */
static QString methodToString(InjectionMethod method)
{
    switch (method) {
    case InjectionMethod::CreateProcessWithDll:
        return "create";
    case InjectionMethod::UpdateRunningProcess:
        return "update";
    case InjectionMethod::HelperProcess:
        return "helper";
    }
    return "create";
}

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);
    QCoreApplication::setApplicationName("AeroPress");
    QCoreApplication::setApplicationVersion("1.0.0");

    // 手动解析参数（QCommandLineParser 不支持重复选项如多个 --dll）
    QStringList args = app.arguments();

    // 检查 --help
    if (args.contains("--help") || args.contains("-h")) {
        printHelp();
        return ExitCode::Success;
    }

    // 解析参数
    QString exePath;
    QStringList dllPaths;
    QString workDir;
    QString gameArgs;
    QString methodStr = "create";
    int timeout = 30;
    DWORD pid = 0;
    bool suspend = false;
    bool verify = false;

    for (int i = 1; i < args.size(); ++i) {
        const QString& arg = args[i];

        if (arg == "--exe" && i + 1 < args.size()) {
            exePath = args[++i];
        } else if (arg == "--dll" && i + 1 < args.size()) {
            dllPaths.append(args[++i]);
        } else if (arg == "--work-dir" && i + 1 < args.size()) {
            workDir = args[++i];
        } else if (arg == "--args" && i + 1 < args.size()) {
            gameArgs = args[++i];
        } else if (arg == "--method" && i + 1 < args.size()) {
            methodStr = args[++i];
        } else if (arg == "--timeout" && i + 1 < args.size()) {
            timeout = args[++i].toInt();
        } else if (arg == "--pid" && i + 1 < args.size()) {
            pid = args[++i].toULong();
        } else if (arg == "--suspend") {
            suspend = true;
        } else if (arg == "--verify") {
            verify = true;
        } else if (arg == "--debug") {
            g_debugOutput = true;
        } else if (arg == "--json") {
            g_jsonOutput = true;
        } else if (arg == "--result-file" && i + 1 < args.size()) {
            g_resultFile = args[++i];
        } else {
            // 未知参数
            return reportError(ExitCode::InvalidArguments,
                "Unknown argument: " + arg,
                "Use --help to see available options");
        }
    }

    debugLog("AeroPress v1.0.0 starting...");

    // 解析注入方法
    InjectionMethod method = parseMethod(methodStr);

    // 参数验证
    // --dll 是所有方法都必需的
    if (dllPaths.isEmpty()) {
        return reportError(ExitCode::InvalidArguments,
            "No DLL paths specified",
            "At least one --dll argument is required");
    }

    // create 方法需要 --exe
    if (method == InjectionMethod::CreateProcessWithDll && exePath.isEmpty()) {
        return reportError(ExitCode::InvalidArguments,
            "Target executable path is required for 'create' method",
            "Use --exe <path> to specify the target executable");
    }

    // update/helper 方法需要 --pid
    if ((method == InjectionMethod::UpdateRunningProcess || method == InjectionMethod::HelperProcess) && pid == 0) {
        return reportError(ExitCode::InvalidArguments,
            "Target process PID is required for '" + methodStr + "' method",
            "Use --pid <pid> to specify the target process");
    }

    // 文件存在性检查
    if (!exePath.isEmpty()) {
        QFileInfo exeInfo(exePath);
        if (!exeInfo.exists()) {
            return reportError(ExitCode::TargetNotFound,
                "Target executable not found",
                "File does not exist: " + exePath);
        }
        debugLog("Target executable: " + exeInfo.absoluteFilePath());
    }

    for (const QString& dllPath : dllPaths) {
        QFileInfo dllInfo(dllPath);
        if (!dllInfo.exists()) {
            return reportError(ExitCode::DllNotFound,
                "DLL file not found",
                "File does not exist: " + dllPath);
        }
        debugLog("DLL to inject: " + dllInfo.absoluteFilePath());
    }

    // 构建注入配置
    InjectionConfig config;
    config.targetExecutable = exePath;
    config.dllPaths = dllPaths;
    config.method = method;
    config.suspendAfterCreation = suspend;
    config.waitForInjection = verify;
    config.timeoutSeconds = timeout;
    config.enableDebugOutput = g_debugOutput;
    config.targetPid = pid;

    if (!workDir.isEmpty()) {
        config.workingDirectory = workDir;
    } else if (!exePath.isEmpty()) {
        config.workingDirectory = QFileInfo(exePath).absolutePath();
    }

    if (!gameArgs.isEmpty()) {
        config.arguments = gameArgs.split(' ', Qt::SkipEmptyParts);
    }

    debugLog("Method: " + methodToString(method));
    debugLog("Timeout: " + QString::number(timeout) + "s");

    // 执行注入（T010 将在此集成 InjectorCore）
    InjectorCore injector;
    InjectionResult result;

    switch (method) {
    case InjectionMethod::CreateProcessWithDll:
        debugLog("Executing CreateProcessWithDll...");
        result = injector.createProcessWithDll(config);
        break;
    case InjectionMethod::UpdateRunningProcess:
        debugLog("Executing UpdateRunningProcess...");
        result = injector.updateRunningProcess(config);
        break;
    case InjectionMethod::HelperProcess:
        debugLog("Executing HelperProcess injection...");
        result = injector.injectViaHelper(config);
        break;
    }

    // 输出结果
    if (result.success) {
        debugLog("Injection succeeded!");
        if (g_jsonOutput) {
            outputJsonSuccess(result);
        } else {
            fprintf(stdout, "Success: %s\n", result.message.toLocal8Bit().constData());
            if (result.processId > 0) {
                fprintf(stdout, "Process ID: %lu\n", result.processId);
            }
        }
        return ExitCode::Success;
    } else {
        debugLog("Injection failed: " + result.error);
        int code = result.exitCode > 0 ? result.exitCode : ExitCode::InjectionFailed;
        return reportError(code, result.error, result.details);
    }
}
