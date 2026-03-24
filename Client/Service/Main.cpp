#include "AhoCorasick/ACScanningEngine.hpp"
#include "AhoCorasick/AhoCorasick.hpp"
#include "AhoCorasick/SCAScanningEngine.hpp"
#include "FileLogger.hpp"
#include "ServerCommunications/ServerCommunications.hpp"
#include "UserConfig.hpp"

#define NOMINMAX
#include <windows.h>
#include <sddl.h>

#include <atomic>
#include <cstdlib>
#include <iostream>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include <nlohmann/json.hpp>

#include "Constants.hpp"
#include "Databases/HashesDatabase.hpp"
#include "KernelCommunications/KernelCommunications.hpp"
#include "ProcessMonitor.hpp"
#include "Protocol.hpp"
#include "Yara/YScanningEngine.hpp"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "Advapi32.lib")

static std::atomic<bool> g_stopMonitoring{false};
static ProcessMonitor *g_monitor = nullptr;

namespace ServicePipeSecurity {
constexpr const char *PIPE_SECURITY_SDDL =
    "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)";

struct PipeSecurityContext {
  SECURITY_ATTRIBUTES attributes{};
  PSECURITY_DESCRIPTOR securityDescriptor = nullptr;

  [[nodiscard]] bool initialize() {
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorA(
            PIPE_SECURITY_SDDL,
            SDDL_REVISION_1,
            &securityDescriptor,
            nullptr)) {
      return false;
    }

    attributes.nLength = sizeof(attributes);
    attributes.lpSecurityDescriptor = securityDescriptor;
    attributes.bInheritHandle = FALSE;
    return true;
  }

  ~PipeSecurityContext() {
    if (securityDescriptor != nullptr) {
      LocalFree(securityDescriptor);
      securityDescriptor = nullptr;
    }
  }
};
} // namespace ServicePipeSecurity

static bool reportSelfTest(bool condition, std::string_view name) {
  if (condition) {
    std::cout << "[PASS] " << name << std::endl;
    return true;
  }

  std::cerr << "[FAIL] " << name << std::endl;
  return false;
}

static int runSelfTests() {
  bool allPassed = true;

  try {
    {
      ACScanningEngine engine({"AA??BB"}, 8);
      const std::vector<uint8_t> data{0xAA, 0x10, 0xBB};
      const auto result = engine.scanMemory(data);
      allPassed &= reportSelfTest(
          result && *result == "AA??BB",
          "ACScanningEngine matches a constrained pattern at byte 0");
    }

    {
      ACScanningEngine engine({"AA??BB*CC"}, 16);
      const std::vector<uint8_t> data{0xAA, 0x11, 0xBB, 0x55, 0x66, 0xCC};
      const auto result = engine.scanMemory(data);
      allPassed &= reportSelfTest(
          result && *result == "AA??BB*CC",
          "ACScanningEngine matches multi-segment wildcard patterns");
    }

    {
      const std::vector<std::vector<uint8_t>> patterns{
          {0xAA, 0xBB},
          {0xBB}};
      const std::vector<uint8_t> data{0xAA, 0xBB};
      const auto matches = AhoCorasick(patterns).search(data);

      bool foundLongMatch = false;
      bool foundSuffixMatch = false;
      for (const auto &match : matches) {
        if (match.patternIndex == 0 && match.startPos == 0 &&
            match.endPos == 1) {
          foundLongMatch = true;
        }
        if (match.patternIndex == 1 && match.startPos == 1 &&
            match.endPos == 1) {
          foundSuffixMatch = true;
        }
      }

      allPassed &= reportSelfTest(
          matches.size() == 2 && foundLongMatch && foundSuffixMatch,
          "AhoCorasick returns every output at the same end position");
    }

    {
      SCAScanningEngine engine({"AA"});
      const std::vector<uint8_t> data{0xAA, 0x00, 0xBB};
      const auto result = engine.scanMemory(data);
      const bool matchesExpectedBytes =
          result && result->size() == 1 &&
          static_cast<unsigned char>((*result)[0]) == 0xAA;
      allPassed &= reportSelfTest(
          matchesExpectedBytes,
          "SCAScanningEngine returns the matched bytes");
    }
  } catch (const std::exception &ex) {
    std::cerr << "[FAIL] Unhandled self-test exception: " << ex.what()
              << std::endl;
    return EXIT_FAILURE;
  }

  return allPassed ? EXIT_SUCCESS : EXIT_FAILURE;
}

static void pipeServerLoop(ProcessMonitor *monitor) {
  std::string pipeName{Constants::AYDO_GUI_PIPE_NAME};
  ServicePipeSecurity::PipeSecurityContext pipeSecurityContext;
  const bool hasCustomPipeSecurity = pipeSecurityContext.initialize();

  if (!hasCustomPipeSecurity) {
    std::cerr << "Failed to initialize named pipe security descriptor, GLE="
              << GetLastError() << std::endl;
  }

  std::cout << "Starting Named Pipe Server at " << pipeName << std::endl;

  while (!g_stopMonitoring.load(std::memory_order_relaxed)) {
    HANDLE hPipe = CreateNamedPipeA(
        pipeName.c_str(),
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        PIPE_UNLIMITED_INSTANCES,
        Constants::PIPE_BUFFER_SIZE,
        Constants::PIPE_BUFFER_SIZE,
        0,
        hasCustomPipeSecurity ? &pipeSecurityContext.attributes : NULL);

    if (hPipe == INVALID_HANDLE_VALUE) {
      std::cerr << "CreateNamedPipe failed, GLE=" << GetLastError()
                << std::endl;
      Sleep(Constants::PIPE_TIMEOUT_MS);
      continue;
    }

    if (ConnectNamedPipe(hPipe, NULL) ||
        GetLastError() == ERROR_PIPE_CONNECTED) {
      std::cout << "Client connected to pipe." << std::endl;

      auto sendEvent = [hPipe](const Protocol::Event &ev) {
        std::string serialized = Protocol::serialize(nlohmann::json(ev));
        DWORD written = 0;
        WriteFile(
            hPipe,
            serialized.c_str(),
            static_cast<DWORD>(serialized.size()),
            &written,
            NULL);
      };

      monitor->setEventHandler([sendEvent](const Protocol::Event &ev) mutable {
        sendEvent(ev);
      });

      monitor->printStatus();
      Protocol::Event capsEv(
          Protocol::EventType::CapabilitiesUpdate,
          "low",
          "Engine capabilities update",
          monitor->getCapabilities());
      sendEvent(capsEv);

      char buffer[Constants::PIPE_BUFFER_SIZE];
      DWORD bytesRead = 0;

      while (!g_stopMonitoring.load(std::memory_order_relaxed)) {
        if (!ReadFile(hPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL)) {
          break;
        }

        buffer[bytesRead] = '\0';
        std::string line(buffer);

        size_t pos = 0;
        while ((pos = line.find('\n')) != std::string::npos) {
          std::string rawCmd = line.substr(0, pos);
          line.erase(0, pos + 1);

          try {
            auto j = nlohmann::json::parse(rawCmd);
            std::string type = j.value("command", "");

            if (type == "ping") {
              sendEvent(Protocol::Event(
                  Protocol::EventType::Heartbeat, "low", "PONG"));
            } else if (type == "status") {
              auto &config = UserConfig::getInstance();
              config.load();
              ServerCommunications::initialize(
                  config.serverUrl, config.accessToken, config.refreshToken);
              monitor->printStatus();
              sendEvent(Protocol::Event(
                  Protocol::EventType::CapabilitiesUpdate,
                  "low",
                  "Capabilities refreshed",
                  monitor->getCapabilities()));
            } else if (type == "scan") {
              std::string path = j.value("path", "");
              if (path.empty()) {
                sendEvent(Protocol::Event(
                    Protocol::EventType::Info,
                    "medium",
                    "Scan command missing path"));
              } else {
                monitor->scanFile(path);
              }
            } else {
              sendEvent(Protocol::Event(
                  Protocol::EventType::Info,
                  "medium",
                  "Unknown command: " + type));
            }
          } catch (const std::exception &e) {
            if (rawCmd == "ping") {
              sendEvent(Protocol::Event(
                  Protocol::EventType::Heartbeat, "low", "PONG"));
            } else {
              sendEvent(Protocol::Event(
                  Protocol::EventType::Info,
                  "medium",
                  "JSON Parse Error: " + std::string(e.what())));
            }
          }
        }
      }
      monitor->setEventHandler(nullptr);
    }

    CloseHandle(hPipe);
    std::cout << "Client disconnected." << std::endl;
  }
}

static BOOL WINAPI CtrlHandler(DWORD t) {
  if (t == CTRL_C_EVENT || t == CTRL_BREAK_EVENT || t == CTRL_CLOSE_EVENT) {
    g_stopMonitoring.store(true, std::memory_order_relaxed);
    if (g_monitor) {
      g_monitor->stop();
    }

    return TRUE;
  }

  return FALSE;
}

int main(int argc, char *argv[]) {
  FileLogger::init();
  FileLogger::log("========== Aydo Process Monitor Starting ==========");

  try {
    if (argc == 2 && std::string_view(argv[1]) == "--self-test") {
      FileLogger::log("Running self-tests");
      return runSelfTests();
    }

    std::cout << "==================================" << std::endl;
    std::cout << "     Aydo Process Monitor" << std::endl;
    std::cout << "==================================" << std::endl
              << std::endl;

    FileLogger::log("Loading user configuration");
    auto &config = UserConfig::getInstance();
    if (!config.load()) {
      std::cout << "Creating default config.json..." << std::endl;
      FileLogger::log("Creating default config.json");
      config.save();
    } else {
      FileLogger::log("Configuration loaded successfully");
    }

    std::cout << "Connecting to server..." << config.serverUrl << std::endl;
    FileLogger::log("Initializing server communications: " + config.serverUrl);
    ServerCommunications::initialize(
        config.serverUrl, config.accessToken, config.refreshToken);

    if (!SetConsoleCtrlHandler(CtrlHandler, TRUE)) {
      std::cerr << "Warning: Could not set Ctrl+C handler" << std::endl;
      FileLogger::log("Warning: Could not set Ctrl+C handler");
    }

    FileLogger::log("Connecting to kernel driver");
    auto driver = KernelCommunications::getInstance();
    std::wstring devicePath{
        Constants::AYDO_DRIVER_DEVICE_PATH.begin(),
        Constants::AYDO_DRIVER_DEVICE_PATH.end()};
    if (!driver->connect(devicePath)) {
      DWORD error = GetLastError();
      std::cerr << "Failed to open driver device. Error: " << error
                << std::endl;
      std::cerr << "Make sure the driver is loaded!" << std::endl;
      FileLogger::error("Failed to connect to driver. Error code: " + std::to_string(error));
      FileLogger::error("Make sure the driver is loaded and service has admin privileges");
      FileLogger::close();
      return EXIT_FAILURE;
    }

    std::cout << "Successfully connected to driver!" << std::endl;
    std::cout << std::endl;
    FileLogger::log("Successfully connected to driver");

    if (!driver->registerSelfAsService()) {
      DWORD error = GetLastError();
      std::cerr << "Failed to register as service. Error: " << error
                << std::endl;
      FileLogger::error("Failed to register as service. Error code: " + std::to_string(error));
      FileLogger::close();
      return EXIT_FAILURE;
    }

    std::cout << "Successfully registered as service!" << std::endl;
    std::cout << "Initializing scanning engines..." << std::endl;
    FileLogger::log("Successfully registered as service");
    FileLogger::log("Initializing scanning engines");

    YScanningEngine yara(Constants::YARA_RULES_FILES, config.killThreshold);
    std::cout << "  -> Initialized YARA scanning engine (Kill Threshold: "
              << config.killThreshold << ")" << std::endl;
    FileLogger::log("Initialized YARA scanning engine (Kill Threshold: " + std::to_string(config.killThreshold) + ")");

    std::string hashesDbPath{
        Constants::HASHES_DB_PATH.begin(), Constants::HASHES_DB_PATH.end()};
    HashesDatabase hashDb(hashesDbPath);
    std::cout << "  -> Loaded hashes database" << std::endl;
    FileLogger::log("Loaded hashes database from: " + hashesDbPath);

    std::cout << "All scanning engines initialized successfully!" << std::endl
              << std::endl;
    FileLogger::log("All scanning engines initialized successfully");

    ProcessMonitor monitor(driver, yara, hashDb);
    g_monitor = &monitor;

    std::cout << "Starting background monitoring thread..." << std::endl;
    FileLogger::log("Starting background monitoring thread");
    monitor.start();

    std::thread commandThread(pipeServerLoop, &monitor);
    commandThread.detach();
    FileLogger::log("Named pipe server started");

    std::cout << "Monitoring active. Press Ctrl+C to stop." << std::endl
              << std::endl;
    FileLogger::log("Service fully initialized and running");

    while (!g_stopMonitoring.load(std::memory_order_relaxed)) {
      Sleep(Constants::IDLE_SLEEP_TIME_MS);
    }

    FileLogger::log("Stopping monitor");
    monitor.stop();
    g_monitor = nullptr;

    std::cout << "Shutting down..." << std::endl;
    FileLogger::log("Service shutting down normally");
    FileLogger::close();
  } catch (const std::exception &ex) {
    std::cerr << "\nFATAL ERROR: Failed to initialize scanning engines: "
              << ex.what() << std::endl;
    FileLogger::error("FATAL ERROR: " + std::string(ex.what()));
    FileLogger::close();
    return EXIT_FAILURE;
  } catch (...) {
    std::cerr << "\nFATAL ERROR: Unknown exception during initialization" << std::endl;
    FileLogger::error("FATAL ERROR: Unknown exception during initialization");
    FileLogger::close();
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}
