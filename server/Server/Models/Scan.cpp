#include "Scan.hpp"

#include <drogon/drogon.h>

using drogon::orm::DbClientPtr;

namespace Models {

Scan::Scan(const drogon::orm::Row &row) {
  try {
    m_id = std::to_string(row["id"].as<int>());
    m_fileHash = row["fileHash"].as<std::string>();
    m_status = stringToStatus(row["status"].as<std::string>());
    m_virusType = stringToVirusType(row["virusType"].as<std::string>());
    m_runtime = row["runtime"].as<int>();
    m_score = row["score"].as<int>();
    m_createdAt =
        trantor::Date::fromDbString(row["createdAt"].as<std::string>());
    m_updatedAt =
        trantor::Date::fromDbString(row["updatedAt"].as<std::string>());
  } catch (const std::exception &e) {
    LOG_WARN << "Failed to parse Scan from row: " << e.what();
  } catch (...) {
    LOG_WARN << "Failed to parse Scan from row: unknown error";
  }
}

std::optional<Scan> Scan::getByFileHash(const DbClientPtr &dbClient,
                                        const std::string &fileHash) {
  try {
    auto result = dbClient->execSqlSync(
        "SELECT id, fileHash, status, virusType, runtime, score, createdAt, updatedAt FROM scans WHERE fileHash = $1 LIMIT 1",
        fileHash);

    if (result.empty()) {
      return std::nullopt;
    }

    return Scan(result[0]);
  } catch (const drogon::orm::DrogonDbException &e) {
    LOG_ERROR << "Database error in Scan::getByFileHash: " << e.base().what();
  } catch (const std::exception &e) {
    LOG_ERROR << "Unexpected error in Scan::getByFileHash: " << e.what();
  } catch (...) {
    LOG_ERROR << "Unexpected unknown error in Scan::getByFileHash";
  }

  return std::nullopt;
}

void Scan::create(const DbClientPtr &dbClient, Scan &scan) {
  try {
    auto result = dbClient->execSqlSync(
        "INSERT INTO scans (fileHash, status, virusType, runtime, score) VALUES ($1, $2, $3, $4, $5) RETURNING id",
        scan.getFileHash(),
        statusToString(scan.getStatus()),
        virusTypeToString(scan.getVirusType()),
        scan.getRuntime(),
        scan.getScore());

    if (!result.empty()) {
      scan.setId(std::to_string(result[0]["id"].as<int>()));
    }
  } catch (const drogon::orm::DrogonDbException &e) {
    LOG_ERROR << "Database error in Scan::create: " << e.base().what();
  } catch (const std::exception &e) {
    LOG_ERROR << "Unexpected error in Scan::create: " << e.what();
  } catch (...) {
    LOG_ERROR << "Unexpected unknown error in Scan::create";
  }
}

void Scan::updateStatus(const DbClientPtr &dbClient,
                        const std::string &fileHash, ScanStatus status) {
  try {
    dbClient->execSqlSync(
        "UPDATE scans SET status = $1, updatedAt = CURRENT_TIMESTAMP WHERE fileHash = $2",
        statusToString(status), fileHash);
  } catch (const drogon::orm::DrogonDbException &e) {
    LOG_ERROR << "Database error in Scan::updateStatus: " << e.base().what();
  } catch (const std::exception &e) {
    LOG_ERROR << "Unexpected error in Scan::updateStatus: " << e.what();
  } catch (...) {
    LOG_ERROR << "Unexpected unknown error in Scan::updateStatus";
  }
}

std::vector<Scan>
Scan::getDueInProgressScans(const DbClientPtr &dbClient) {
  std::vector<Scan> scans;
  try {
    auto result = dbClient->execSqlSync(
        "SELECT id, fileHash, status, virusType, runtime, score, createdAt, updatedAt "
        "FROM scans "
        "WHERE status = $1 "
        "AND createdAt <= CURRENT_TIMESTAMP - (runtime || ' seconds')::interval",
        statusToString(ScanStatus::InProgress));

    scans.reserve(result.size());
    for (const auto &row : result) {
      scans.emplace_back(row);
    }
  } catch (const drogon::orm::DrogonDbException &e) {
    LOG_ERROR << "Database error in Scan::getDueInProgressScans: "
              << e.base().what();
  } catch (const std::exception &e) {
    LOG_ERROR << "Unexpected error in Scan::getDueInProgressScans: "
              << e.what();
  } catch (...) {
    LOG_ERROR << "Unexpected unknown error in Scan::getDueInProgressScans";
  }

  return scans;
}

void Scan::updateResult(const DbClientPtr &dbClient, const std::string &fileHash,
                        ScanStatus status, VirusType virusType, int score) {
  try {
    dbClient->execSqlSync(
        "UPDATE scans SET status = $1, virusType = $2, score = $3, updatedAt = CURRENT_TIMESTAMP WHERE fileHash = $4",
        statusToString(status), virusTypeToString(virusType), score, fileHash);
  } catch (const drogon::orm::DrogonDbException &e) {
    LOG_ERROR << "Database error in Scan::updateResult: " << e.base().what();
  } catch (const std::exception &e) {
    LOG_ERROR << "Unexpected error in Scan::updateResult: " << e.what();
  } catch (...) {
    LOG_ERROR << "Unexpected unknown error in Scan::updateResult";
  }
}

void Scan::resetScan(const DbClientPtr &dbClient, const std::string &fileHash,
                     int runtime) {
  try {
    dbClient->execSqlSync(
        "UPDATE scans SET status = $1, virusType = $2, score = $3, runtime = $4, updatedAt = CURRENT_TIMESTAMP WHERE fileHash = $5",
        statusToString(ScanStatus::Pending), virusTypeToString(VirusType::Clean),
        0, runtime, fileHash);
  } catch (const drogon::orm::DrogonDbException &e) {
    LOG_ERROR << "Database error in Scan::resetScan: " << e.base().what();
  } catch (const std::exception &e) {
    LOG_ERROR << "Unexpected error in Scan::resetScan: " << e.what();
  } catch (...) {
    LOG_ERROR << "Unexpected unknown error in Scan::resetScan";
  }
}

std::string Scan::statusToString(ScanStatus status) {
  switch (status) {
  case ScanStatus::Pending:
    return "Pending";
  case ScanStatus::InProgress:
    return "InProgress";
  case ScanStatus::Completed:
    return "Completed";
  case ScanStatus::Failed:
    return "Failed";
  default:
    return "Unknown";
  }
}

ScanStatus Scan::stringToStatus(const std::string &str) {
  if (str == "Pending") {
    return ScanStatus::Pending;
  }
  if (str == "InProgress") {
    return ScanStatus::InProgress;
  }
  if (str == "Completed") {
    return ScanStatus::Completed;
  }
  if (str == "Failed") {
    return ScanStatus::Failed;
  }

  return ScanStatus::Unknown;
}

std::string Scan::virusTypeToString(VirusType type) {
  switch (type) {
  case VirusType::Clean:
    return "Clean";
  case VirusType::Trojan:
    return "Trojan";
  case VirusType::Worm:
    return "Worm";
  case VirusType::Ransomware:
    return "Ransomware";
  case VirusType::Spyware:
    return "Spyware";
  case VirusType::Adware:
    return "Adware";
  case VirusType::Rootkit:
    return "Rootkit";
  case VirusType::Unknown:
  default:
    return "Unknown";
  }
}

VirusType Scan::stringToVirusType(const std::string &str) {
  if (str == "Clean") {
    return VirusType::Clean;
  }
  if (str == "Trojan") {
    return VirusType::Trojan;
  }
  if (str == "Worm") {
    return VirusType::Worm;
  }
  if (str == "Ransomware") {
    return VirusType::Ransomware;
  }
  if (str == "Spyware") {
    return VirusType::Spyware;
  }
  if (str == "Adware") {
    return VirusType::Adware;
  }
  if (str == "Rootkit") {
    return VirusType::Rootkit;
  }
  if (str == "Unknown") {
    return VirusType::Unknown;
  }
  return VirusType::Unknown;
}

} // namespace Models
