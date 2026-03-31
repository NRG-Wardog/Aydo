#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <WinSock2.h>
#include <Windows.h>

#include "VmRunner.hpp"

#include <algorithm>
#include <cstdlib>
#include <cwctype>
#include <filesystem>
#include <format>
#include <functional>
#include <map>
#include <string>
#include <thread>
#include <vector>

#include <drogon/drogon.h>

#include "SandboxRuntimeConfig.hpp"

namespace Utils::VmRunner {
namespace {

struct CaseInsensitiveWideLess {
  bool operator()(const std::wstring &lhs, const std::wstring &rhs) const {
    return std::lexicographical_compare(
        lhs.begin(), lhs.end(), rhs.begin(), rhs.end(),
        [](wchar_t a, wchar_t b) {
          return std::towlower(a) < std::towlower(b);
        });
  }
};

std::wstring utf8ToWide(const std::string &value) {
  if (value.empty()) {
    return {};
  }

  const int size =
      MultiByteToWideChar(CP_UTF8, 0, value.c_str(), -1, nullptr, 0);
  if (size <= 1) {
    return {};
  }

  std::wstring wide(static_cast<size_t>(size - 1), L'\0');
  MultiByteToWideChar(CP_UTF8, 0, value.c_str(), -1, wide.data(), size);
  return wide;
}

std::wstring quoteWindowsArgument(std::wstring_view value) {
  if (value.empty()) {
    return L"\"\"";
  }

  if (value.find_first_of(L" \t\n\v\"") == std::wstring_view::npos) {
    return std::wstring(value);
  }

  std::wstring out;
  out.push_back(L'"');
  size_t backslashCount = 0;
  for (wchar_t ch : value) {
    if (ch == L'\\') {
      ++backslashCount;
      continue;
    }
    if (ch == L'"') {
      out.append(backslashCount * 2 + 1, L'\\');
      out.push_back(L'"');
      backslashCount = 0;
      continue;
    }
    if (backslashCount != 0) {
      out.append(backslashCount, L'\\');
      backslashCount = 0;
    }
    out.push_back(ch);
  }
  if (backslashCount != 0) {
    out.append(backslashCount * 2, L'\\');
  }
  out.push_back(L'"');
  return out;
}

std::vector<wchar_t> buildCommandLine(
    const std::filesystem::path &executablePath,
    const std::vector<std::string> &arguments) {
  std::wstring commandLine = quoteWindowsArgument(executablePath.wstring());
  for (const auto &argument : arguments) {
    commandLine.push_back(L' ');
    commandLine += quoteWindowsArgument(utf8ToWide(argument));
  }

  std::vector<wchar_t> buffer(commandLine.begin(), commandLine.end());
  buffer.push_back(L'\0');
  return buffer;
}

void readPipeToString(HANDLE pipeHandle, std::string &buffer) {
  constexpr DWORD CHUNK_SIZE = 16 * 1024;
  std::vector<char> chunk(CHUNK_SIZE);
  DWORD bytesRead = 0;
  while (ReadFile(pipeHandle, chunk.data(), CHUNK_SIZE, &bytesRead, nullptr) &&
         bytesRead != 0) {
    buffer.append(chunk.data(), chunk.data() + bytesRead);
  }
}

std::vector<wchar_t> buildEnvironmentBlock(
    const std::vector<std::pair<std::string, std::string>> &overrides) {
  std::map<std::wstring, std::wstring, CaseInsensitiveWideLess> merged;
  if (LPWCH env = GetEnvironmentStringsW()) {
    for (LPCWCH cursor = env; *cursor != L'\0';) {
      const std::wstring entry(cursor);
      cursor += entry.size() + 1;

      const size_t separator =
          entry.find(L'=', !entry.empty() && entry.front() == L'=' ? 1 : 0);
      if (separator == std::wstring::npos) {
        continue;
      }

      merged[entry.substr(0, separator)] = entry.substr(separator + 1);
    }
    FreeEnvironmentStringsW(env);
  }

  for (const auto &[name, value] : overrides) {
    merged[utf8ToWide(name)] = utf8ToWide(value);
  }

  std::wstring block;
  for (const auto &[name, value] : merged) {
    block += name;
    block.push_back(L'=');
    block += value;
    block.push_back(L'\0');
  }
  block.push_back(L'\0');

  return std::vector<wchar_t>(block.begin(), block.end());
}

} // namespace

bool startVm(const std::string &sandboxId,
             const std::filesystem::path &payloadHostPath,
             int runtimeSeconds) {
  const auto configResult =
      Utils::SandboxRuntimeConfig::load(drogon::app().getCustomConfig());
  if (!configResult) {
    LOG_ERROR << "Sandbox config error: " << configResult.error;
    return false;
  }

  const auto &config = *configResult.config;
  const std::filesystem::path resolvedVmRunnerPath =
      config.vmRunnerPath.is_absolute()
          ? config.vmRunnerPath
          : std::filesystem::absolute(config.vmRunnerPath);

  if (!std::filesystem::exists(resolvedVmRunnerPath)) {
    LOG_ERROR << "VMRunner path does not exist: " << resolvedVmRunnerPath.string();
    return false;
  }

  const std::filesystem::path resolvedPayloadPath =
      std::filesystem::absolute(payloadHostPath);
  if (!std::filesystem::exists(resolvedPayloadPath)) {
    LOG_ERROR << "Payload path does not exist: " << resolvedPayloadPath.string();
    return false;
  }

  std::vector<wchar_t> childEnvironment =
      buildEnvironmentBlock(config.toEnvironment());
  std::vector<wchar_t> commandLine = buildCommandLine(
      resolvedVmRunnerPath,
      {sandboxId, resolvedPayloadPath.string(), std::to_string(runtimeSeconds)});

  SECURITY_ATTRIBUTES securityAttributes{};
  securityAttributes.nLength = sizeof(securityAttributes);
  securityAttributes.bInheritHandle = TRUE;

  HANDLE stdoutRead = nullptr;
  HANDLE stdoutWrite = nullptr;
  HANDLE stderrRead = nullptr;
  HANDLE stderrWrite = nullptr;

  if (!CreatePipe(&stdoutRead, &stdoutWrite, &securityAttributes, 0) ||
      !SetHandleInformation(stdoutRead, HANDLE_FLAG_INHERIT, 0) ||
      !CreatePipe(&stderrRead, &stderrWrite, &securityAttributes, 0) ||
      !SetHandleInformation(stderrRead, HANDLE_FLAG_INHERIT, 0)) {
    LOG_ERROR << "Failed to create pipes for VMRunner process output";
    if (stdoutRead != nullptr) {
      CloseHandle(stdoutRead);
    }
    if (stdoutWrite != nullptr) {
      CloseHandle(stdoutWrite);
    }
    if (stderrRead != nullptr) {
      CloseHandle(stderrRead);
    }
    if (stderrWrite != nullptr) {
      CloseHandle(stderrWrite);
    }
    return false;
  }

  STARTUPINFOW startupInfo{};
  startupInfo.cb = sizeof(startupInfo);
  startupInfo.dwFlags = STARTF_USESTDHANDLES;
  startupInfo.hStdOutput = stdoutWrite;
  startupInfo.hStdError = stderrWrite;
  startupInfo.hStdInput = nullptr;

  PROCESS_INFORMATION processInfo{};
  const std::wstring workingDirectory = resolvedVmRunnerPath.parent_path().wstring();

  LOG_INFO << "Launching VMRunner: " << resolvedVmRunnerPath.string()
           << " sandboxId=" << sandboxId
           << " runtimeSeconds=" << runtimeSeconds
           << " payload=" << resolvedPayloadPath.string()
           << " sandboxDir=" << config.sandboxDirectoryFor(sandboxId).string()
           << " expectedLogDb=" << config.sharedLogDbPath(sandboxId).string();
  const BOOL processCreated = CreateProcessW(
      resolvedVmRunnerPath.c_str(),
      commandLine.data(),
      nullptr,
      nullptr,
      TRUE,
      CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
      childEnvironment.empty() ? nullptr : childEnvironment.data(),
      workingDirectory.empty() ? nullptr : workingDirectory.c_str(),
      &startupInfo,
      &processInfo);

  CloseHandle(stdoutWrite);
  CloseHandle(stderrWrite);

  if (!processCreated) {
    const DWORD lastError = GetLastError();
    LOG_ERROR << "CreateProcessW failed for VMRunner: " << lastError;
    CloseHandle(stdoutRead);
    CloseHandle(stderrRead);
    return false;
  }

  std::string stdoutBuffer;
  std::string stderrBuffer;
  std::jthread stdoutThread(readPipeToString, stdoutRead,
                            std::ref(stdoutBuffer));
  std::jthread stderrThread(readPipeToString, stderrRead,
                            std::ref(stderrBuffer));

  WaitForSingleObject(processInfo.hProcess, INFINITE);
  DWORD processExitCode = EXIT_FAILURE;
  (void)GetExitCodeProcess(processInfo.hProcess, &processExitCode);

  CloseHandle(processInfo.hThread);
  CloseHandle(processInfo.hProcess);
  CloseHandle(stdoutRead);
  CloseHandle(stderrRead);

  stdoutThread.join();
  stderrThread.join();

  if (!stdoutBuffer.empty()) {
    LOG_DEBUG << "VMRunner stdout (sandboxId=" << sandboxId << "):\n"
              << stdoutBuffer;
  }
  if (!stderrBuffer.empty()) {
    LOG_WARN << "VMRunner stderr (sandboxId=" << sandboxId << "):\n"
             << stderrBuffer;
  }

  const int rc = static_cast<int>(processExitCode);
  if (rc != 0) {
    LOG_ERROR << "VMRunner failed with exit code " << rc
              << " (sandboxId=" << sandboxId << ")";
    return false;
  }

  LOG_INFO << "VMRunner completed successfully (sandboxId=" << sandboxId << ")";
  return true;
}

} // namespace Utils::VmRunner
