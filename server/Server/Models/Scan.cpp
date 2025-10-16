#include "Scan.hpp"

#include <drogon/orm/DbClient.h>

namespace Models {

using drogon::orm::DbClientPtr;

Scan::Scan(const drogon::orm::Row &row) {
  try {
    m_id = std::to_string(row["id"].as<int>());
    m_fileHash = row["fileHash"].as<std::string>();
    m_runtime = row["runtime"].as<int>();
    m_status = static_cast<ScanStatus>(row["status"].as<int>());
    m_virusType = static_cast<VirusType>(row["virusType"].as<int>());
    m_score = row["score"].as<double>();
  } catch (const std::exception &e) {
    LOG_WARN << "Failed to parse Scan from row: " << e.what();
  } catch (...) {
    LOG_WARN << "Failed to parse Scan from row: unknown error";
  }
}

std::optional<Scan> Scan::getByFileHash(const DbClientPtr &dbClient,
                                        const std::string &fileHash) {
  if (fileHash.empty()) {
    return std::nullopt;
  }

  auto result = dbClient->execSqlSync(
      "SELECT id, fileHash, runtime, status, virusType, score FROM scans WHERE fileHash = $1 LIMIT 1",
      fileHash);

  if (result.empty()) {
    return std::nullopt;
  }

  const auto &row = result[0];

  Scan scan(row);

  return scan;
}

std::optional<Scan> Scan::getById(const DbClientPtr &dbClient,
                                  const std::string &id) {
  if (id.empty()) {
    return std::nullopt;
  }

  auto result = dbClient->execSqlSync(
      "SELECT id, fileHash, runtime, status, virusType, score FROM scans WHERE id = $1 LIMIT 1",
      id);

  if (result.empty()) {
    return std::nullopt;
  }

  const auto &row = result[0];

  Scan scan(row);

  return scan;
}

void Scan::create(const DbClientPtr &dbClient, Scan &scan) {
  auto result = dbClient->execSqlSync(
      "INSERT INTO scans (fileHash, runtime, status, virusType, score) VALUES ($1, $2, $3, $4, $5) RETURNING id",
      scan.getFileHash(), scan.getRuntime(), scan.getStatus(), scan.getVirusType(), scan.getScore());

  if (!result.empty()) {
    scan.setId(std::to_string(result[0]["id"].as<int>()));
  }
}

void Scan::update(const DbClientPtr &dbClient, Scan &scan) {
  dbClient->execSqlSync(
      "UPDATE scans SET runtime = $1, status = $2, virusType = $3, score = $4, updatedAt = $5 WHERE id = $6",
      scan.getRuntime(), scan.getStatus(), scan.getVirusType(), scan.getScore(), trantor::Date::now(), scan.getId());
}

} // namespace Models