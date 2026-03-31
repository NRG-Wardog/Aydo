#define NOMINMAX
#include "Utills.hpp"

#include <Windows.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <format>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "Constants.hpp"
#include "LogName.hpp"

namespace Utills {

namespace {

std::string trimCopy(std::string value) {
  const auto isNotSpace = [](unsigned char ch) {
    return !std::isspace(ch);
  };
  const auto first = std::find_if(value.begin(), value.end(), isNotSpace);
  if (first == value.end()) {
    return {};
  }
  const auto last =
      std::find_if(value.rbegin(), value.rend(), isNotSpace).base();
  return std::string(first, last);
}

std::string singleLineForLog(std::string value, size_t maxLen = 320) {
  std::replace(value.begin(), value.end(), '\r', ' ');
  std::replace(value.begin(), value.end(), '\n', ' ');
  value = trimCopy(std::move(value));
  if (value.size() <= maxLen) {
    return value;
  }
  return value.substr(0, maxLen) + "...";
}

} // namespace

void printBanner(bool isClosing) {
  std::string bannerStr(BANNER);
  std::vector<std::string> lines;
  std::stringstream ss(bannerStr);
  std::string line;

  while (std::getline(ss, line))
    lines.push_back(line);

  // Print banner once without clearing the console to avoid wiping user output.
  // Keep the parameter to preserve the existing call sites/signature.
  (void)isClosing;
  for (const auto &ln : lines)
    std::cout << ln << '\n';
  std::cout << std::endl;
}

static std::wstring utf8ToWide(const std::string &s) {
  if (s.empty()) {
    return std::wstring();
  }
  const int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
  std::wstring w(n - 1, L'\0');
  MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, w.data(), n);

  return w;
}

static void readPipeToString(HANDLE hPipe, std::string &out) {
  constexpr DWORD CHUNK_SIZE = 16 * 1024;
  std::vector<char> buf(CHUNK_SIZE);
  DWORD read = 0;
  for (;;) {
    if (!ReadFile(hPipe, buf.data(), CHUNK_SIZE, &read, nullptr) || read == 0)
      break;
    out.append(buf.data(), buf.data() + read);
  }
}

int executeAndWaitRC(const std::string &cmdUtf8,
                     std::string *out,
                     std::string *err,
                     std::chrono::milliseconds timeout,
                     bool echoOutput) {
  SECURITY_ATTRIBUTES sa{};
  sa.nLength = sizeof(sa);
  sa.bInheritHandle = TRUE;

  HANDLE outRead = nullptr;
  HANDLE outWrite = nullptr;
  HANDLE errRead = nullptr;
  HANDLE errWrite = nullptr;

  if (!CreatePipe(&outRead, &outWrite, &sa, 0)) {
    return -1;
  }
  if (!SetHandleInformation(outRead, HANDLE_FLAG_INHERIT, 0)) {
    return -1;
  }
  if (!CreatePipe(&errRead, &errWrite, &sa, 0)) {
    return -1;
  }
  if (!SetHandleInformation(errRead, HANDLE_FLAG_INHERIT, 0)) {
    return -1;
  }

  STARTUPINFOW si{};
  si.cb = sizeof(si);
  si.dwFlags = STARTF_USESTDHANDLES;
  si.hStdOutput = outWrite;
  si.hStdError = errWrite;
  si.hStdInput = nullptr;

  PROCESS_INFORMATION pi{};

  std::wstring cmdW = utf8ToWide(cmdUtf8);
  std::vector<wchar_t> cmdBuf(cmdW.begin(), cmdW.end());
  cmdBuf.push_back(L'\0');

  BOOL ok = CreateProcessW(
      nullptr, cmdBuf.data(),
      nullptr, nullptr,
      TRUE, CREATE_NO_WINDOW,
      nullptr, nullptr,
      &si, &pi);

  CloseHandle(outWrite);
  outWrite = nullptr;
  CloseHandle(errWrite);
  errWrite = nullptr;

  if (!ok) {
    const DWORD le = GetLastError();
    std::cerr << "CreateProcessW failed for cmd: " << cmdUtf8
              << " (GetLastError=" << le << ")\n";
    CloseHandle(outRead);
    CloseHandle(errRead);
    return -1;
  }

  std::string outBuf;
  std::string errBuf;
  std::jthread tOut(readPipeToString, outRead, std::ref(outBuf));
  std::jthread tErr(readPipeToString, errRead, std::ref(errBuf));

  DWORD waitMs = (timeout == std::chrono::milliseconds::max())
                     ? INFINITE
                     : static_cast<DWORD>(timeout.count());
  DWORD wr = WaitForSingleObject(pi.hProcess, waitMs);

  int rc = -1;
  if (wr == WAIT_TIMEOUT) {
    constexpr DWORD EXITCODE_TIMEOUT_GNU = 124;
    TerminateProcess(pi.hProcess, EXITCODE_TIMEOUT_GNU);
    WaitForSingleObject(pi.hProcess, INFINITE);
    rc = EXITCODE_TIMEOUT_GNU;
  } else {
    DWORD code = 0;
    if (GetExitCodeProcess(pi.hProcess, &code))
      rc = static_cast<int>(code);
  }

  CloseHandle(pi.hThread);
  CloseHandle(pi.hProcess);
  CloseHandle(outRead);
  CloseHandle(errRead);

  tOut.join();
  tErr.join();

  if (echoOutput) {
    if (!outBuf.empty())
      std::cout << outBuf;
    if (!errBuf.empty())
      std::cerr << errBuf;
  }

  if (out)
    *out = std::move(outBuf);
  if (err)
    *err = std::move(errBuf);
  return rc;
}
std::string dequote(std::string s) {
  if (s.size() >= 2 && s.front() == '"' && s.back() == '"')
    s = s.substr(1, s.size() - 2);

  return s;
}

bool waitForTools(const std::string &vmRunPath,
                  const std::string &sandboxPath,
                  int maxRetries,
                  int sleepMs) {
  const std::string vmrun = winQuote(dequote(vmRunPath));
  const std::string vmx = winQuote(dequote(sandboxPath));
  const std::string full =
      std::format(R"({} -T ws checkToolsState {})", vmrun, vmx);

  for (int i = 0; i < maxRetries; ++i) {
    std::string output;
    std::string error;
    const int rc = executeAndWaitRC(
        full,
        &output,
        &error,
        std::chrono::seconds(15),
        false);

    std::string lower = output;
    lower += '\n';
    lower += error;
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    const std::string summary = singleLineForLog(
        output.empty() ? error : output + (error.empty() ? "" : " " + error));
    std::cout << "    [tools] probe " << (i + 1) << '/' << maxRetries
              << ": rc=" << rc;
    if (!summary.empty()) {
      std::cout << " output=" << summary;
    }
    std::cout << std::endl;

    if (rc == 0 && lower.find("not running") == std::string::npos &&
        lower.find("running") != std::string::npos) {
      return true;
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(sleepMs));
  }
  return false;
}

int runPSInGuest(const std::string &vmRunPath,
                 const std::string &sandboxVmx,
                 std::string_view psCommand) {
  const std::string psPath = R"(C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe)";
  const std::string quotedVmRunPath = winQuote(dequote(vmRunPath));
  const std::string cmd = std::format(
      R"({} -T ws -gu {} -gp {} runProgramInGuest {} {} -NoLogo -NoProfile -NonInteractive -Command {})",
      quotedVmRunPath, std::string(GUEST_USER), std::string(GUEST_PASS),
      sandboxVmx, ensureQuoted(psPath), psQuote(std::string(psCommand)));
  return executeAndWaitRC(cmd);
}

bool guestPathExists(const std::string &vmRunPath,
                     const std::string &sandboxVmx,
                     std::string_view guestPath) {
  const std::string cmd = std::format(
      R"(if (Test-Path {}) {{ exit 0 }} else {{ exit 1 }})",
      psQuote(std::string(guestPath)));
  return runPSInGuest(vmRunPath, sandboxVmx, cmd) == 0;
}

static std::string normalizeVmPathForComparison(std::string path) {
  path = dequote(std::move(path));
  const auto isNotSpace = [](unsigned char ch) {
    return !std::isspace(ch);
  };
  const auto first = std::find_if(path.begin(), path.end(), isNotSpace);
  if (first == path.end()) {
    return {};
  }
  const auto last =
      std::find_if(path.rbegin(), path.rend(), isNotSpace).base();
  path = std::string(first, last);
  std::replace(path.begin(), path.end(), '/', '\\');
  for (size_t i = 1; i < path.size(); ++i) {
    if (path[i] == '\\' && path[i - 1] == '\\')
      path.erase(i--, 1);
  }
  std::transform(path.begin(), path.end(), path.begin(),
                 [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return path;
}

std::string vmPowerStateToString(VmPowerState state) {
  switch (state) {
    case VmPowerState::Running:
      return "Running";
    case VmPowerState::Stopped:
      return "Stopped";
    case VmPowerState::Unknown:
      return "Unknown";
  }
  return "Unknown";
}

VmPowerStateDetails probeVmPowerState(const std::string &vmRunPath,
                                      const std::string &sandboxVmx) {
  VmPowerStateDetails details;
  details.command =
      std::format(R"({} -T ws list)", winQuote(dequote(vmRunPath)));
  details.rc = executeAndWaitRC(
      details.command,
      &details.out,
      &details.err,
      std::chrono::seconds(10),
      false);
  if (details.rc != 0) {
    details.state = VmPowerState::Unknown;
    return details;
  }

  const std::string expected = normalizeVmPathForComparison(sandboxVmx);
  std::istringstream stream(details.out);
  std::string line;
  while (std::getline(stream, line)) {
    if (normalizeVmPathForComparison(line) == expected) {
      details.state = VmPowerState::Running;
      return details;
    }
  }

  details.state = VmPowerState::Stopped;
  return details;
}

VmPowerState getVmPowerState(const std::string &vmRunPath,
                             const std::string &sandboxVmx) {
  return probeVmPowerState(vmRunPath, sandboxVmx).state;
}

bool waitForVmPowerState(const VmPowerStateProvider &provider,
                         VmPowerState desiredState,
                         int maxRetries,
                         int sleepMs) {
  for (int attempt = 0; attempt < maxRetries; ++attempt) {
    if (provider() == desiredState) {
      return true;
    }

    if (attempt + 1 < maxRetries) {
      std::this_thread::sleep_for(std::chrono::milliseconds(sleepMs));
    }
  }

  return provider() == desiredState;
}

bool waitForVmToStart(const std::string &vmRunPath,
                      const std::string &sandboxVmx,
                      int maxRetries,
                      int sleepMs) {
  return waitForVmPowerState(
      [&]() { return getVmPowerState(vmRunPath, sandboxVmx); },
      VmPowerState::Running,
      maxRetries,
      sleepMs);
}

static bool waitForVmToStop(const std::string &vmRunPath,
                            const std::string &sandboxVmx,
                            std::chrono::milliseconds timeout,
                            std::chrono::milliseconds pollInterval =
                                std::chrono::milliseconds(500)) {
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  while (std::chrono::steady_clock::now() < deadline) {
    if (getVmPowerState(vmRunPath, sandboxVmx) == VmPowerState::Stopped) {
      return true;
    }
    std::this_thread::sleep_for(pollInterval);
  }
  return getVmPowerState(vmRunPath, sandboxVmx) == VmPowerState::Stopped;
}

bool closeVM(const std::string &vmRunPath, const std::string &sandboxVmx,
             const std::string &sandboxId) {
  (void)sandboxId;
  std::cout << "[6.1/7] Stop VM (soft)" << std::endl;
  const std::string quotedVmRunPath = winQuote(dequote(vmRunPath));
  const std::string softCmd =
      std::format(R"({} -T ws stop {} soft)", quotedVmRunPath, sandboxVmx);
  const int softRc = Utills::executeAndWaitRC(softCmd);
  if (softRc == 0 &&
      waitForVmToStop(
          vmRunPath,
          sandboxVmx,
          std::chrono::milliseconds(VM_SHUTDOWN_GRACE_MS))) {
    return true;
  }
  if (softRc != 0 &&
      getVmPowerState(vmRunPath, sandboxVmx) == VmPowerState::Stopped) {
    return true;
  }

  std::cout << "[6.2/7] Stop VM (hard)" << std::endl;
  const std::string hardCmd =
      std::format(R"({} -T ws stop {} hard)", quotedVmRunPath, sandboxVmx);
  const int hardRc = Utills::executeAndWaitRC(hardCmd);
  if (hardRc != 0 &&
      getVmPowerState(vmRunPath, sandboxVmx) != VmPowerState::Stopped) {
    return false;
  }

  return waitForVmToStop(
      vmRunPath,
      sandboxVmx,
      std::chrono::milliseconds(VM_SHUTDOWN_GRACE_MS));
}

bool closeVMWithExecutor(const std::string &vmRunPath,
                         const std::string &sandboxVmx,
                         const CommandExecutor &executor,
                         std::chrono::seconds fallbackDelay) {
  std::cout << "[6.1/7] Stop VM (soft)" << std::endl;
  {
    const std::string softCmd =
        std::format(R"({} -T ws stop {} soft)", vmRunPath, sandboxVmx);
    if (executor(softCmd) == 0) {
      return true;
    }
  }

  if (fallbackDelay > std::chrono::seconds::zero()) {
    std::this_thread::sleep_for(fallbackDelay);
  }

  std::cout << "[6.2/7] Stop VM (hard)" << std::endl;
  {
    const std::string hardCmd =
        std::format(R"({} -T ws stop {} hard)", vmRunPath, sandboxVmx);
    return executor(hardCmd) == 0;
  }
}

std::string ensureQuoted(const std::string &s) {
  if (!s.empty() && s.front() == '"' && s.back() == '"') {
    return s;
  }
  return std::format(R"("{}")", s);
}

std::string psQuote(const std::string &s) {
  std::string out;
  out.reserve(s.size() + 2);
  out.push_back('\'');
  for (char c : s) {
    if (c == '\'')
      out += "''";
    else
      out.push_back(c);
  }
  out.push_back('\'');
  return out;
}

std::string winQuote(std::string_view s) {
  if (const bool need = s.empty() || s.find_first_of(" \t\n\v\"") != std::string_view::npos; !need)
    return std::string(s);

  std::string out;
  out.push_back('"');
  size_t bs = 0;

  for (char c : s) {
    if (c == '\\') {
      ++bs;
      continue;
    }
    if (c == '"') {
      out.append(bs * 2 + 1, '\\'); // escape quote
      out.push_back('"');
      bs = 0;
      continue;
    }
    if (bs) {
      out.append(bs, '\\');
      bs = 0;
    }
    out.push_back(c);
  }
  if (bs)
    out.append(bs * 2, '\\');
  out.push_back('"');
  return out;
}

} // namespace Utills
