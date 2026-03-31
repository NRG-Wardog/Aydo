#include "ScanProcessingCron.hpp"

#include <drogon/HttpAppFramework.h>
#include <drogon/orm/DbClient.h>
#include <sqlite3.h>
#include <trantor/utils/Logger.h>

#include <filesystem>
#include <fstream>
#include <json/json.h>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

#include "../Constants.hpp"

#include "Generic.hpp"
#include "SandboxRuntimeConfig.hpp"

namespace Utils::ScanProcessingCron {
struct SigmaQuery {
  std::string query;
  std::string level;
};

int levelToScore(const std::string &level) {
  if (level == "critical") {
    return 100;
  }
  if (level == "high") {
    return 75;
  }
  if (level == "medium") {
    return 25;
  }
  if (level == "low") {
    return 5;
  }
  if (level == "informational") {
    return 1;
  }
  return 0;
}

std::optional<std::filesystem::path> resolveSigmaQueriesPath() {
  for (const auto *candidate : Constants::SIGMA_QUERY_PATHS) {
    std::filesystem::path path(candidate);
    if (std::filesystem::exists(path)) {
      return std::filesystem::absolute(path);
    }
  }
  return std::nullopt;
}

std::string buildExistsQuery(const std::string &rawQuery) {
  std::string cleaned = Utils::Generic::trim(rawQuery);
  while (!cleaned.empty() && cleaned.back() == ';') {
    cleaned.pop_back();
  }
  if (cleaned.empty()) {
    return {};
  }
  std::ostringstream oss;
  oss << "SELECT 1 FROM (" << cleaned << ") AS sigma_subquery LIMIT 1";
  return oss.str();
}

const std::vector<SigmaQuery> &getSigmaQueries(bool &loadedSuccessfully) {
  static std::vector<SigmaQuery> queries;
  static bool loaded = false;
  static std::once_flag once;

  std::call_once(once, []() {
    const auto queriesPath = resolveSigmaQueriesPath();
    if (!queriesPath.has_value()) {
      LOG_ERROR << "Sigma queries file not found (expected at ../data or data).";
      return;
    }

    std::ifstream in(queriesPath->string());
    if (!in) {
      LOG_ERROR << "Failed to open Sigma queries file at "
                << queriesPath->string();
      return;
    }

    Json::CharReaderBuilder builder;
    std::string errs;
    Json::Value root;
    if (!Json::parseFromStream(builder, in, &root, &errs)) {
      LOG_ERROR << "Failed to parse Sigma queries JSON (" << errs << ")";
      return;
    }

    if (!root.isArray()) {
      LOG_ERROR << "Sigma queries JSON is not an array";
      return;
    }

    queries.reserve(root.size());
    for (const auto &entry : root) {
      if (entry.isObject()) {
        std::string query = entry.get("query", "").asString();
        std::string level = entry.get("level", "unknown").asString();
        if (!query.empty()) {
          queries.push_back({query, level});
        }
      } else if (entry.isString()) {
        queries.push_back({entry.asString(), "unknown"});
      }
    }

    loaded = true;
    LOG_INFO << "Loaded " << queries.size()
             << " Sigma queries for dynamic scanning.";
  });

  loadedSuccessfully = loaded;
  return queries;
}

DynamicScanOutcome runDynamicScan(const Models::Scan &scan) {
  LOG_DEBUG << "[DynamicScan] Scanning fileHash=" << scan.getFileHash();

  const auto sandboxConfigResult =
      Utils::SandboxRuntimeConfig::load(drogon::app().getCustomConfig());
  if (!sandboxConfigResult) {
    LOG_ERROR << "Sandbox config error while processing dynamic scan: "
              << sandboxConfigResult.error;
    return {Models::ScanStatus::Failed, Models::VirusType::Unknown, 0};
  }

  bool queriesLoaded = false;
  const auto &queries = getSigmaQueries(queriesLoaded);
  if (!queriesLoaded || queries.empty()) {
    LOG_ERROR << "Sigma queries unavailable; marking scan as failed.";
    return {Models::ScanStatus::Failed, Models::VirusType::Unknown, 0};
  }

  const std::filesystem::path logDbPath =
      sandboxConfigResult.config->sharedLogDbPath(scan.getFileHash());
  const std::string logDbPathStr = logDbPath.string();

  sqlite3 *db = nullptr;
  const int openCode = sqlite3_open_v2(
      logDbPathStr.c_str(), &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_NOMUTEX, nullptr);
  if (openCode != SQLITE_OK || db == nullptr) {
    LOG_ERROR << "Failed to open log database at " << logDbPathStr
              << ": " << (db ? sqlite3_errmsg(db) : "unknown error");
    if (db) {
      sqlite3_close(db);
    }
    return {Models::ScanStatus::Failed, Models::VirusType::Unknown, 0};
  }

  sqlite3_busy_timeout(db, BUSY_TIMEOUT_MS);
  sqlite3_exec(db, "PRAGMA query_only = ON;", nullptr, nullptr, nullptr);

  int maxScore = 0;
  bool anyMatch = false;

  for (const auto &sigma : queries) {
    const auto existsQuery = buildExistsQuery(sigma.query);
    if (existsQuery.empty()) {
      continue;
    }

    sqlite3_stmt *stmt = nullptr;
    const int prepareCode =
        sqlite3_prepare_v2(db, existsQuery.c_str(), -1, &stmt, nullptr);
    if (prepareCode != SQLITE_OK) {
      LOG_WARN << "Skipping Sigma query due to prepare error: "
               << sqlite3_errmsg(db);
      if (stmt) {
        sqlite3_finalize(stmt);
      }
      continue;
    }

    const int stepCode = sqlite3_step(stmt);
    const bool matched = (stepCode == SQLITE_ROW);
    sqlite3_finalize(stmt);

    if (matched) {
      anyMatch = true;
      int currentScore = levelToScore(sigma.level);
      if (currentScore > maxScore) {
        maxScore = currentScore;
      }

      LOG_INFO << "Sigma match found for fileHash=" << scan.getFileHash()
               << " level=" << sigma.level << " score=" << currentScore;

      // If we find a critical hit, we can stop early
      if (maxScore >= 100) {
        break;
      }
    }
  }

  sqlite3_close(db);

  if (anyMatch) {
    return {Models::ScanStatus::Completed, Models::VirusType::Unknown, maxScore};
  }

  return {Models::ScanStatus::Completed, Models::VirusType::Clean, 0};
}

double resolveProcessingIntervalSeconds(const Json::Value &customConfig) {
  if (customConfig.isMember(Constants::PROCESSING_CRON_INTERVAL_KEY.data())) {
    const auto &value =
        customConfig[Constants::PROCESSING_CRON_INTERVAL_KEY.data()];
    if (value.isNumeric()) {
      const double parsed = value.asDouble();
      if (parsed > 0.0) {
        return parsed;
      }
    }
  }

  return Constants::DEFAULT_SCAN_CHECK_INTERVAL_S;
}

void processDueScans(const drogon::orm::DbClientPtr &dbClient) {
  try {
    const auto dueScans = Models::Scan::getDueInProgressScans(dbClient);

    for (const auto &scan : dueScans) {
      LOG_INFO << "Processing scan (fileHash=" << scan.getFileHash()
               << ", runtime=" << scan.getRuntime() << "s)";

      const auto outcome = runDynamicScan(scan);
      Models::Scan::updateResult(dbClient, scan.getFileHash(),
                                 outcome.status, outcome.virusType,
                                 outcome.score);
    }
  } catch (const std::exception &e) {
    LOG_ERROR << "Processing cron failed: " << e.what();
  } catch (...) {
    LOG_ERROR << "Processing cron failed: unknown error";
  }
}

void startProcessingCron() {
  auto dbClient = drogon::app().getDbClient();
  const auto customConfig = drogon::app().getCustomConfig();
  const double intervalSeconds = resolveProcessingIntervalSeconds(customConfig);

  drogon::app().getLoop()->runEvery(intervalSeconds, [dbClient]() {
    processDueScans(dbClient);
  });
}

} // namespace Utils::ScanProcessingCron
