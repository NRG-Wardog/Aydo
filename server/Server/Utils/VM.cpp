#define NOMINMAX

#include "VM.hpp"

#include <Windows.h>

#include <filesystem>
#include <format>
#include <string>
#include <string_view>
#include <vector>

#include "trantor/utils/Logger.h"

#include "../Constants.hpp"

bool Utils::VM::startVM(const std::string &sandboxId,
                        const std::string &payloadPath,
                        unsigned int runtimeSeconds) {
  const auto runnerPath = Constants::DEFAULT_VM_RUNNER_PATH;
  const std::wstring runnerPathW(runnerPath.begin(), runnerPath.end());

  std::filesystem::path payloadHostPath(payloadPath);
  std::error_code ec;
  payloadHostPath = std::filesystem::absolute(payloadHostPath, ec);
  if (ec || !std::filesystem::exists(payloadHostPath)) {
    LOG_ERROR << "Payload path does not exist: " << payloadHostPath.string();
    return false;
  }

  const std::wstring sandboxIdW(sandboxId.begin(), sandboxId.end());
  const std::wstring payloadPathW = payloadHostPath.wstring();

  std::wstring commandLine = std::format(L"{} {} {} {}", runnerPathW, sandboxIdW, payloadPathW, runtimeSeconds);

  std::vector<wchar_t> mutableCmd(commandLine.begin(), commandLine.end());
  mutableCmd.push_back(L'\0');

  STARTUPINFOW si{};
  si.cb = sizeof(si);
  PROCESS_INFORMATION pi{};

  const BOOL createOk = CreateProcessW(runnerPathW.c_str(),
                                       mutableCmd.data(),
                                       nullptr,
                                       nullptr,
                                       FALSE,
                                       CREATE_NO_WINDOW,
                                       nullptr,
                                       nullptr,
                                       &si,
                                       &pi);

  if (!createOk) {
    LOG_ERROR << "Failed to start VMRunner.exe (error " << GetLastError() << ")";
    return false;
  }

  LOG_INFO << "Launched VMRunner.exe for sandbox " << sandboxId << " (PID=" << pi.dwProcessId << ")";

  CloseHandle(pi.hThread);
  CloseHandle(pi.hProcess);

  return true;
}
