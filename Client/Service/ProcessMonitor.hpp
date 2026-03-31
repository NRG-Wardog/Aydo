#pragma once

#include <atomic>
#include <chrono>
#include <future>
#include <memory>
#include <mutex>
#include <nlohmann/json.hpp>
#include <optional>
#include <string>
#include <thread>
#include <unordered_map>

#include <functional>
#include "Databases/HashesDatabase.hpp"
#include "KernelCommunications/KernelCommunications.hpp"
#include "Yara/YScanningEngine.hpp"

#include "Protocol.hpp"

using EventCallback = std::function<void(const Protocol::Event &)>;

class ProcessMonitor {
private:
  enum class FastScanResult { Clean,
                              Threat,
                              NeedsDeepScan };

  struct FastScanOutcome {
    FastScanResult result;
    std::string hexHash;
  };

  std::shared_ptr<KernelCommunications> m_driver;
  YScanningEngine &m_yara;
  const HashesDatabase &m_hashDb;

  std::atomic<bool> m_stopMonitoring{false};
  std::unordered_map<std::string, bool> m_scannedHashes;
  std::unordered_map<std::string, std::shared_future<bool>> m_pendingScans;
  std::mutex m_cacheMutex;
  std::mutex m_pendingMutex;
  std::thread m_monitorThread;
  EventCallback m_eventHandler;
  std::mutex m_loggerMutex;

public:
  ProcessMonitor(std::shared_ptr<KernelCommunications> driver,
                 YScanningEngine &yara,
                 const HashesDatabase &hashDb);
  ~ProcessMonitor();

  ProcessMonitor(const ProcessMonitor &) = delete;
  ProcessMonitor &operator=(const ProcessMonitor &) = delete;

  void setEventHandler(EventCallback handler);
  void log(const std::string &message);

  void start();
  void stop();
  void printStatus();
  nlohmann::json getCapabilities();

  bool isMonitoring() const;
  bool scanFile(const std::string &path,
                const std::string &scanDepth = "standard");

  bool isThreat(const std::string &path);
  void setBlockingActive(bool active);

private:
  std::atomic<bool> m_blockingActive{false};
  void monitorLoop();

  FastScanOutcome fastScan(const std::string &path);
  bool deepScan(const std::string &path, const std::string &hash,
                bool forceCloud = false);
  bool dynamicScan(const std::string &path, const std::string &hash,
                   const std::chrono::steady_clock::time_point &outerStart);
  void notify(Protocol::EventType, std::string, std::string,
              nlohmann::json = {});
  void cacheResult(const std::string &hash, bool isThreat);
  void safeResume(uint32_t pid, const std::string &path);
  void killAndCleanup(uint32_t pid, const std::string &path);
  void applyFileVerdict(const std::string &path, bool threat);

  bool scanDirectory(const std::string &path);
  void handleProcessStarted(uint32_t pid, const std::string &path);
};
