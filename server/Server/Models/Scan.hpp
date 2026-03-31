#pragma once

#include <drogon/orm/DbClient.h>
#include <drogon/orm/Result.h>
#include <optional>
#include <string>
#include <trantor/utils/Date.h>
#include <vector>

namespace Models {

enum class ScanStatus {
  Pending,
  InProgress,
  Completed,
  Failed,
  Unknown
};

enum class VirusType {
  Clean,
  Trojan,
  Worm,
  Ransomware,
  Spyware,
  Adware,
  Rootkit,
  Unknown
};

class Scan {
private:
  std::string m_id;
  std::string m_fileHash;
  ScanStatus m_status = ScanStatus::Pending;
  VirusType m_virusType = VirusType::Clean;
  int m_runtime = 0;
  int m_score = 0;
  trantor::Date m_createdAt;
  trantor::Date m_updatedAt;

public:
  Scan() = default;
  explicit Scan(const drogon::orm::Row &row);

  static std::optional<Scan> getByFileHash(
      const drogon::orm::DbClientPtr &dbClient, const std::string &fileHash);

  static void create(const drogon::orm::DbClientPtr &dbClient, Scan &scan);

  static void updateStatus(const drogon::orm::DbClientPtr &dbClient,
                           const std::string &fileHash, ScanStatus status);

  static std::vector<Scan>
  getDueInProgressScans(const drogon::orm::DbClientPtr &dbClient);

  static void updateResult(const drogon::orm::DbClientPtr &dbClient,
                           const std::string &fileHash, ScanStatus status,
                           VirusType virusType, int score);

  static void resetScan(const drogon::orm::DbClientPtr &dbClient,
                        const std::string &fileHash, int runtime);

  [[nodiscard]] static std::string statusToString(ScanStatus status);
  [[nodiscard]] static ScanStatus stringToStatus(const std::string &str);
  [[nodiscard]] static std::string virusTypeToString(VirusType type);
  [[nodiscard]] static VirusType stringToVirusType(const std::string &str);

  [[nodiscard]] const std::string &getId() const { return m_id; }
  [[nodiscard]] const std::string &getFileHash() const { return m_fileHash; }
  [[nodiscard]] ScanStatus getStatus() const { return m_status; }
  [[nodiscard]] VirusType getVirusType() const { return m_virusType; }
  [[nodiscard]] int getRuntime() const { return m_runtime; }
  [[nodiscard]] int getScore() const { return m_score; }
  [[nodiscard]] const trantor::Date &getCreatedAt() const { return m_createdAt; }
  [[nodiscard]] const trantor::Date &getUpdatedAt() const { return m_updatedAt; }

  void setId(const std::string &id) { m_id = id; }
  void setFileHash(const std::string &fileHash) { m_fileHash = fileHash; }
  void setStatus(ScanStatus status) { m_status = status; }
  void setVirusType(VirusType type) { m_virusType = type; }
  void setRuntime(int runtime) { m_runtime = runtime; }
  void setScore(int score) { m_score = score; }
  void setCreatedAt(const trantor::Date &createdAt) { m_createdAt = createdAt; }
  void setUpdatedAt(const trantor::Date &updatedAt) { m_updatedAt = updatedAt; }
};

} // namespace Models
