#include "ProcessMonitor.hpp"

#include <windows.h>

#include <array>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <future>
#include <iostream>
#include <utility>
#include <vector>

#include "Constants.hpp"
#include "FileLogger.hpp"
#include "ServerCommunications/ServerCommunications.hpp"
#include "UserConfig.hpp"
#include "Utils.hpp"

using namespace std::chrono_literals;

// ─── Internal helpers ────────────────────────────────────────────────────────

namespace {

long long msElapsed(const std::chrono::steady_clock::time_point &from) {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::steady_clock::now() - from)
      .count();
}

const char *boolStr(bool v) { return v ? "true" : "false"; }

} // namespace

// ─── Construction / Destruction ──────────────────────────────────────────────

ProcessMonitor::ProcessMonitor(std::shared_ptr<KernelCommunications> driver,
                               YScanningEngine &yara,
                               const HashesDatabase &hashDb)
    : m_driver(std::move(driver))
    , m_yara(yara)
    , m_hashDb(hashDb) {}

ProcessMonitor::~ProcessMonitor() {
  stop();
}

// ─── Public API ──────────────────────────────────────────────────────────────

void ProcessMonitor::setEventHandler(EventCallback handler) {
  std::lock_guard<std::mutex> lock(m_loggerMutex);
  m_eventHandler = std::move(handler);
}

void ProcessMonitor::start() {
  if (m_monitorThread.joinable()) {
    std::cerr << "[WARNING] Monitor thread is already running\n";
    return;
  }
  m_stopMonitoring.store(false, std::memory_order_relaxed);
  m_monitorThread = std::thread(&ProcessMonitor::monitorLoop, this);
  log("Process monitoring started");
}

void ProcessMonitor::stop() {
  if (!m_monitorThread.joinable())
    return;
  m_stopMonitoring.store(true, std::memory_order_relaxed);
  m_monitorThread.join();
  log("Process monitoring stopped");
}

bool ProcessMonitor::isMonitoring() const {
  return !m_stopMonitoring.load(std::memory_order_relaxed) && m_monitorThread.joinable();
}

void ProcessMonitor::setBlockingActive(bool active) {
  m_blockingActive.store(active, std::memory_order_relaxed);
}

void ProcessMonitor::printStatus() {
  log("Process monitoring started");
  if (m_driver)
    log("Successfully connected to driver");
  log("Loaded hashes database");
  log("Initialized YARA scanning engine");
  log("[ENTROPY] Monitoring active");

  const auto &config = UserConfig::getInstance();
  const bool hasTokens = !config.accessToken.empty() || !config.refreshToken.empty();

  if (!config.serverUrl.empty() && hasTokens)
    log("Connecting to server... " + config.serverUrl);
  else
    log("[CLOUD] Disabled (guest mode or missing auth tokens)");
}

nlohmann::json ProcessMonitor::getCapabilities() {
  const auto &config = UserConfig::getInstance();
  const bool hasTokens = !config.accessToken.empty() || !config.refreshToken.empty();
  return {
      {"driver", m_driver != nullptr},
      {"hashdb", true},
      {"yara", true},
      {"entropy", true},
      {"cloud", !config.serverUrl.empty() && hasTokens},
  };
}

// ─── Public scan API ─────────────────────────────────────────────────────────

bool ProcessMonitor::scanFile(const std::string &path) {
  const auto start = std::chrono::steady_clock::now();
  log("[SCAN] path=" + path);

  if (path.empty()) {
    FileLogger::error("[SCAN] Missing path");
    return false;
  }
  if (!std::filesystem::exists(path)) {
    FileLogger::error("[SCAN] File not found: " + path);
    return false;
  }
  if (std::filesystem::is_directory(path))
    return scanDirectory(path);

  try {
    const auto &config = UserConfig::getInstance();
    const auto fileSize = std::filesystem::file_size(path);
    if (config.maxScanSize > 0 && fileSize > config.maxScanSize) {
      log("[SCAN] Skipped (too large, " + std::to_string(fileSize) + " bytes): " + path);
      return false;
    }
  } catch (const std::exception &ex) {
    FileLogger::error("[SCAN] Metadata error: " + std::string(ex.what()));
    return false;
  }

  notify(Protocol::EventType::ScanProgress, "low",
         "Scanning: " + std::filesystem::path(path).filename().string(),
         {{"target", path}});

  try {
    const bool threat = isThreat(path);
    log("[SCAN] Done threat=" + std::string(boolStr(threat)) +
        " totalMs=" + std::to_string(msElapsed(start)));
    applyFileVerdict(path, threat);
    return threat;
  } catch (const std::exception &ex) {
    FileLogger::error("[SCAN] Exception: " + std::string(ex.what()));
    return false;
  }
}

bool ProcessMonitor::scanDirectory(const std::string &path) {
  notify(Protocol::EventType::ScanProgress, "low",
         "Starting directory scan: " + path,
         {{"target", path}, {"progress", 0}});

  std::vector<std::filesystem::path> files;
  try {
    for (const auto &entry : std::filesystem::recursive_directory_iterator(path))
      if (entry.is_regular_file())
        files.push_back(entry.path());
  } catch (const std::exception &ex) {
    notify(Protocol::EventType::Info, "medium",
           "Failed to iterate directory: " + std::string(ex.what()),
           {{"target", path}});
    return false;
  }

  if (files.empty()) {
    notify(Protocol::EventType::ScanComplete, "low",
           "CLEAN: " + path + " (empty)",
           {{"target", path}, {"threats", 0}});
    return false;
  }

  size_t threats = 0;
  for (size_t i = 0; i < files.size(); ++i) {
    const std::string filePath = files[i].string();
    const int progress = static_cast<int>(
        (i + 1) * Constants::SCAN_PROGRESS_PERCENTAGE_MAX / files.size());

    std::string displayName;
    try {
      displayName = std::filesystem::relative(files[i], path).string();
    } catch (...) {
      displayName = files[i].filename().string();
    }

    notify(Protocol::EventType::ScanProgress, "low",
           "Scanning: " + displayName,
           {{"target", path}, {"progress", progress}});

    try {
      if (isThreat(filePath)) {
        ++threats;
        notify(Protocol::EventType::ThreatDetected, "high",
               "THREAT: " + filePath, {{"target", filePath}});
        applyFileVerdict(filePath, true);
      }
    } catch (...) {
    }
  }

  const bool hadThreats = threats > 0;
  notify(Protocol::EventType::ScanComplete,
         hadThreats ? "high" : "low",
         "Scan complete. " + (hadThreats
                                  ? "Threats found: " + std::to_string(threats)
                                  : std::string("Clean.")),
         {{"target", path}, {"threats", threats}});

  return hadThreats;
}

// ─── Scan layers ─────────────────────────────────────────────────────────────
//
//  fastScan  (L1–L3) — O(ms): signing check, in-memory cache, hash DB
//  deepScan  (L4–L6) — O(seconds): YARA, entropy, cloud/dynamic
//
//  handleProcessStarted runs fastScan first. If the result is definitive it acts
//  immediately. If a deep scan is needed it fires it asynchronously and resumes
//  the process after SLOW_SCAN_RESUME_TIMEOUT_S seconds rather than blocking the
//  user, then kills the process if the final verdict comes back as a threat.

ProcessMonitor::FastScanOutcome ProcessMonitor::fastScan(const std::string &path) {
  // L1 ── Windows signing check
  const auto l1Start = std::chrono::steady_clock::now();
  if (Utils::isWindowsSigned(path)) {
    log("[L1] Windows-signed -> clean ms=" + std::to_string(msElapsed(l1Start)));
    return {FastScanResult::Clean, {}};
  }
  log("[L1] Not signed ms=" + std::to_string(msElapsed(l1Start)));

  // Compute hash once — shared by the cache check and hash DB lookup.
  const auto hashStart = std::chrono::steady_clock::now();
  const std::string hash = Utils::computeSHA256(path);
  if (hash.empty()) {
    FileLogger::error("[L2] SHA-256 failed for: " + path);
    return {FastScanResult::Clean, {}};
  }
  const std::string hashPrefix = hash.substr(0, 12);
  log("[L2] hash=" + hashPrefix + " ms=" + std::to_string(msElapsed(hashStart)));

  // L2 ── In-memory cache
  {
    const auto cacheStart = std::chrono::steady_clock::now();
    bool hasCachedVerdict = false;
    bool cachedVerdict = false;
    size_t cacheSize = 0;

    {
      std::lock_guard<std::mutex> lock(m_cacheMutex);
      cacheSize = m_scannedHashes.size();
      if (auto it = m_scannedHashes.find(hash); it != m_scannedHashes.end()) {
        hasCachedVerdict = true;
        cachedVerdict = it->second;
      }
    }

    log("[L2] cache size=" + std::to_string(cacheSize) +
        " checking hash=" + hashPrefix);

    if (hasCachedVerdict) {
      log("[L2] Cache hit verdict=" + std::string(boolStr(cachedVerdict)) +
          " ms=" + std::to_string(msElapsed(cacheStart)));
      return {cachedVerdict ? FastScanResult::Threat : FastScanResult::Clean, hash};
    }

    log("[L2] Cache miss ms=" + std::to_string(msElapsed(cacheStart)));
  }

  // L3 ── Hash database
  const auto dbStart = std::chrono::steady_clock::now();
  if (const auto name = m_hashDb.getHashName(hash); name && !name->empty()) {
    cacheResult(hash, true);
    log("[L3] Hash DB match name=" + *name + " ms=" + std::to_string(msElapsed(dbStart)));
    return {FastScanResult::Threat, hash};
  }
  log("[L3] Hash DB clean ms=" + std::to_string(msElapsed(dbStart)));

  return {FastScanResult::NeedsDeepScan, hash};
}

bool ProcessMonitor::deepScan(const std::string &path, const std::string &hash) {
  const auto scanStart = std::chrono::steady_clock::now();
  const std::string pfx = hash.substr(0, 12);

  // L4 ── YARA scoring
  const auto yaraStart = std::chrono::steady_clock::now();
  const auto yaraResult = m_yara.scanFileWithScoring(path);
  log("[L4] YARA matches=" + std::to_string(yaraResult.matchedRules.size()) +
      " score=" + std::to_string(yaraResult.scoring.totalScore) +
      " shouldKill=" + std::string(boolStr(yaraResult.scoring.shouldKill)) +
      " ms=" + std::to_string(msElapsed(yaraStart)));

  if (yaraResult.hasMatches()) {
    if (yaraResult.scoring.shouldKill) {
      cacheResult(hash, true);
      return true;
    }

    // Score is noise-level — treat as clean without going further.
    if (yaraResult.scoring.highestLevel <= ThreatLevel::Info &&
        yaraResult.matchedRules.size() < Constants::YARA_INFO_MATCH_THRESHOLD) {
      cacheResult(hash, false);
      log("[L4] YARA below threshold -> clean totalMs=" +
          std::to_string(msElapsed(scanStart)));
      return false;
    }
  }

  // L5 ── Auth token / guest-mode gate
  const auto &config = UserConfig::getInstance();
  const bool hasTokens = !config.accessToken.empty() || !config.refreshToken.empty();
  if (!hasTokens) {
    cacheResult(hash, false);
    log("[L5] No auth tokens -> defaulting clean totalMs=" +
        std::to_string(msElapsed(scanStart)));
    return false;
  }

  // L5 ── Server reachability
  bool serverReachable = false;
  if (!config.serverUrl.empty()) {
    try {
      serverReachable = ServerCommunications::getInstance().isServerReachable();
    } catch (...) {
    }
  }
  log("[L5] Server reachable=" + std::string(boolStr(serverReachable)));

  if (!serverReachable) {
    cacheResult(hash, false);
    log("[L5] Server unreachable -> defaulting clean totalMs=" +
        std::to_string(msElapsed(scanStart)));
    return false;
  }

  // L6 ── Entropy gate before dynamic scan
  const auto entropyStart = std::chrono::steady_clock::now();
  const auto bytes = Utils::readFile(path);
  std::array<int, Constants::ALPHABET_SIZE> freq{};
  for (uint8_t b : bytes)
    ++freq[b];

  const double entropy = Utils::calculateEntropy(
      std::vector<int>(freq.begin(), freq.end()),
      static_cast<std::streamsize>(bytes.size()));
  log("[L6] Entropy=" + std::to_string(entropy) +
      " threshold=" + std::to_string(config.entropyThreshold) +
      " ms=" + std::to_string(msElapsed(entropyStart)));

  if (entropy > config.entropyThreshold) {
    const bool threat = dynamicScan(path, hash, scanStart);
    if (threat)
      return true;
  }

  cacheResult(hash, false);
  log("[THREAT] Final verdict CLEAN totalMs=" + std::to_string(msElapsed(scanStart)));
  return false;
}

bool ProcessMonitor::dynamicScan(const std::string &path,
                                 const std::string &hash,
                                 const std::chrono::steady_clock::time_point &outerStart) {
  const auto &config = UserConfig::getInstance();
  auto &server = ServerCommunications::getInstance();

  bool fileUploaded = false;
  int pollCount = 0;
  const auto maxWait = std::chrono::milliseconds(Constants::DYNAMIC_SCAN_MAX_WAIT_MS);
  const auto dynStart = std::chrono::steady_clock::now();

  while (std::chrono::steady_clock::now() - dynStart < maxWait) {
    ++pollCount;
    nlohmann::json response;

    if (!server.requestFileScan(hash, config.runtime, response)) {
      FileLogger::error("[L6] requestFileScan failed");
      break;
    }

    const std::string status = response.value("status", "Unknown");
    log("[L6] Poll#" + std::to_string(pollCount) + " status=" + status +
        " elapsedMs=" + std::to_string(msElapsed(dynStart)));

    if (status == "Completed") {
      const std::string virusType = response.value("virusType", "Unknown");
      const int score = response.value("score", 0);
      const bool threat = virusType != "Clean" || score > config.dynamicScanThreshold;
      cacheResult(hash, threat);
      log("[L6] Completed virusType=" + virusType +
          " score=" + std::to_string(score) +
          " threat=" + std::string(boolStr(threat)) +
          " totalMs=" + std::to_string(msElapsed(outerStart)));
      return threat;
    }

    if (status == "Pending" && !fileUploaded) {
      if (!server.uploadFile(hash, path)) {
        FileLogger::error("[L6] Upload failed for: " + path);
        break;
      }
      fileUploaded = true;
      log("[L6] File uploaded for dynamic scan");
    } else if (status == "Failed") {
      FileLogger::error("[L6] Server reported Failed for: " + path);
      break;
    }

    Sleep(Constants::DYNAMIC_SCAN_CLIENT_POLL_MS);
  }

  log("[L6] Dynamic scan ended without verdict after " +
      std::to_string(pollCount) + " polls");
  return false;
}

bool ProcessMonitor::isThreat(const std::string &path) {
  log("[THREAT] Begin path=" + path);
  auto [result, hash] = fastScan(path);
  if (result == FastScanResult::Threat)
    return true;
  if (result == FastScanResult::Clean)
    return false;
  return deepScan(path, hash);
}

void ProcessMonitor::handleProcessStarted(uint32_t pid, const std::string &path) {
  try {
    auto [fastResult, hash] = fastScan(path);

    if (fastResult == FastScanResult::Threat) {
      killAndCleanup(pid, path);
      return;
    }
    if (fastResult == FastScanResult::Clean) {
      safeResume(pid, path);
      return;
    }

    std::shared_future<bool> scanFuture;
    bool reusedInFlightScan = false;

    {
      std::lock_guard<std::mutex> lock(m_pendingMutex);
      if (auto it = m_pendingScans.find(hash); it != m_pendingScans.end()) {
        reusedInFlightScan = true;
        scanFuture = it->second;
      } else {
        std::promise<bool> promise;
        scanFuture = promise.get_future().share();
        m_pendingScans[hash] = scanFuture;

        std::thread([this, path, hash, p = std::move(promise)]() mutable {
          try {
            p.set_value(deepScan(path, hash));
          } catch (...) {
            p.set_value(false);
          }
          std::lock_guard<std::mutex> lock(m_pendingMutex);
          m_pendingScans.erase(hash);
        }).detach();
      }
    }

    if (reusedInFlightScan) {
      log("[SCAN] Hash already in-flight, sharing result for PID=" +
          std::to_string(pid));

      safeResume(pid, path);
      std::thread([this, pid, path, scanFuture]() mutable {
        try {
          const bool threat = scanFuture.get();
          if (threat) {
            log("[SCAN] Late shared verdict THREAT for PID=" + std::to_string(pid));
            killAndCleanup(pid, path);
          } else {
            log("[SCAN] Late shared verdict CLEAN for PID=" + std::to_string(pid));
          }
        } catch (const std::exception &ex) {
          FileLogger::error("[SCAN] Late shared verdict exception on PID=" +
                            std::to_string(pid) + ": " + ex.what());
        } catch (...) {
          FileLogger::error("[SCAN] Late shared verdict unknown exception on PID=" +
                            std::to_string(pid));
        }
      }).detach();
      return;
    }

    const auto timeout = std::chrono::seconds(Constants::SLOW_SCAN_RESUME_TIMEOUT_S);
    if (scanFuture.wait_for(timeout) == std::future_status::ready) {
      const bool threat = scanFuture.get();
      if (threat) {
        killAndCleanup(pid, path);
      } else {
        safeResume(pid, path);
      }
      return;
    }

    safeResume(pid, path);
    log("[SCAN] Deep scan still running after " +
        std::to_string(Constants::SLOW_SCAN_RESUME_TIMEOUT_S) +
        "s; resumed PID=" + std::to_string(pid) +
        " and waiting for late verdict");

    std::thread([this, pid, path, scanFuture]() mutable {
      try {
        const bool threat = scanFuture.get();
        if (threat) {
          log("[SCAN] Late verdict THREAT for PID=" + std::to_string(pid));
          killAndCleanup(pid, path);
        } else {
          log("[SCAN] Late verdict CLEAN for PID=" + std::to_string(pid));
        }
      } catch (const std::exception &ex) {
        FileLogger::error("[SCAN] Late verdict exception on PID=" +
                          std::to_string(pid) + ": " + ex.what());
      } catch (...) {
        FileLogger::error("[SCAN] Late verdict unknown exception on PID=" +
                          std::to_string(pid));
      }
    }).detach();

  } catch (const std::exception &ex) {
    FileLogger::error("[SCAN] Exception on PID=" + std::to_string(pid) +
                      ": " + ex.what());
    safeResume(pid, path);
  } catch (...) {
    FileLogger::error("[SCAN] Unknown exception on PID=" + std::to_string(pid));
    safeResume(pid, path);
  }
}

void ProcessMonitor::monitorLoop() {
  const DWORD selfPid = GetCurrentProcessId();

  while (!m_stopMonitoring.load(std::memory_order_relaxed)) {
    auto notification = m_driver->getProcessNotification();

    if (!notification.has_value()) {
      Sleep(Constants::SLEEP_BETWEEN_NO_NOTIFICATIONS_MS);
      continue;
    }

    if (!notification->IsCreated)
      continue;
    if (m_blockingActive.load(std::memory_order_relaxed))
      continue;
    if (notification->ProcessId == selfPid)
      continue;

    const std::wstring wpath = Utils::resolve_process_path(
        notification->ProcessId, notification->ImageFileName);
    const std::string path = Utils::wstring_to_utf8(wpath);
    if (path.empty())
      continue;

    log("[PROC] Start PID=" + std::to_string(notification->ProcessId) +
        " image=" + Utils::wstring_to_utf8(notification->ImageFileName) +
        " path=" + path);

    std::thread(&ProcessMonitor::handleProcessStarted,
                this, notification->ProcessId, path)
        .detach();
  }
}

void ProcessMonitor::notify(Protocol::EventType type,
                            std::string severity,
                            std::string message,
                            nlohmann::json data) {
  const std::string typeStr = Protocol::eventTypeToString(type);
  const std::string formatted = "[" + typeStr + "][" + severity + "] " + message;

  if (severity == "high") {
    std::cerr << formatted << "\n";
    FileLogger::error(formatted);
  } else {
    if (severity == "medium") {
      std::cout << formatted << "\n";
    }
    FileLogger::log(formatted);
  }

  EventCallback eventHandler;
  {
    std::lock_guard<std::mutex> lock(m_loggerMutex);
    eventHandler = m_eventHandler;
  }

  const bool shouldForwardToGui =
      !(type == Protocol::EventType::Info && severity == "low");

  if (!shouldForwardToGui || !eventHandler) {
    return;
  }

  try {
    eventHandler(Protocol::Event(
        type, std::move(severity), std::move(message), std::move(data)));
  } catch (const std::exception &ex) {
    FileLogger::error("[EVENT] Failed to forward to GUI: " + std::string(ex.what()));
  } catch (...) {
    FileLogger::error("[EVENT] Failed to forward to GUI: unknown exception");
  }
}

void ProcessMonitor::log(const std::string &message) {
  notify(Protocol::EventType::Info, "low", message);
}

void ProcessMonitor::cacheResult(const std::string &hash, bool isThreat) {
  size_t newSize = 0;
  {
    std::lock_guard<std::mutex> lock(m_cacheMutex);
    m_scannedHashes[hash] = isThreat;
    newSize = m_scannedHashes.size();
  }

  log("[CACHE] Stored hash=" + hash.substr(0, 12) +
      " verdict=" + std::string(boolStr(isThreat)) +
      " size=" + std::to_string(newSize));
}

void ProcessMonitor::safeResume(uint32_t pid, const std::string &path) {
  if (m_driver->resumeProcess(pid)) {
    log("[PROC] Resumed PID=" + std::to_string(pid) + " path=" + path);
  } else {
    const DWORD error = GetLastError();
    FileLogger::error("[PROC] Failed to resume PID=" + std::to_string(pid) +
                      " path=" + path + " GLE=" + std::to_string(error));
    notify(Protocol::EventType::Info,
           "high",
           "Failed to resume PID=" + std::to_string(pid),
           {{"target", path}, {"pid", pid}, {"gle", error}});
  }
}

void ProcessMonitor::killAndCleanup(uint32_t pid, const std::string &path) {
  notify(Protocol::EventType::ThreatDetected, "high",
         "MALICIOUS: " + path, {{"target", path}, {"pid", pid}});

  if (m_driver->killProcess(pid))
    notify(Protocol::EventType::Info, "medium",
           "Terminated PID=" + std::to_string(pid));
  else
    notify(Protocol::EventType::Info, "high",
           "FAILED to terminate PID=" + std::to_string(pid));

  applyFileVerdict(path, true);
}

void ProcessMonitor::applyFileVerdict(const std::string &path, bool threat) {
  if (!threat) {
    notify(Protocol::EventType::ScanComplete, "low",
           "CLEAN: " + path, {{"target", path}, {"threats", 0}});
    return;
  }

  const auto &config = UserConfig::getInstance();
  if (config.infectedFileAction == Constants::INFECTED_FILE_ACTION_QUARANTINE) {
    if (Utils::quarantineFile(path))
      notify(Protocol::EventType::Quarantine, "medium",
             "Isolated: " + path, {{"target", path}});
    else
      notify(Protocol::EventType::Info, "medium",
             "Failed to quarantine: " + path, {{"target", path}});
  } else if (config.infectedFileAction == Constants::INFECTED_FILE_ACTION_DELETE) {
    if (Utils::deleteFile(path))
      notify(Protocol::EventType::Delete, "medium",
             "Removed: " + path, {{"target", path}});
    else
      notify(Protocol::EventType::Info, "medium",
             "Failed to delete: " + path, {{"target", path}});
  }
}