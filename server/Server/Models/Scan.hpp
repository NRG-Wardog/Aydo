#pragma once

#include <drogon/orm/CoroMapper.h>
#include <drogon/orm/DbClient.h>
#include <drogon/orm/Mapper.h>
#include <drogon/orm/Result.h>
#include <optional>
#include <trantor/utils/Date.h>

namespace Models {
enum class ScanStatus {
  Pending = 0,
  InProgress = 1,
  Completed = 2
};

enum class VirusType {
  Clean = 0,
  CredentialStealer = 1,
  Persistence = 2,
  Ransomware = 3,
  Trojan = 4,
  Other = 5
};

class Scan {
private:
  std::string m_id{};
  std::string m_fileHash{};
  int m_runtime{};
  ScanStatus m_status{ScanStatus::Pending};
  VirusType m_virusType{VirusType::Clean};
  double m_score{0.0};
  trantor::Date m_createdAt{};
  trantor::Date m_updatedAt{};

public:
  Scan() = default;
  explicit Scan(const drogon::orm::Row &row);

  static std::optional<Scan> getByFileHash(
      const drogon::orm::DbClientPtr &dbClient, const std::string &fileHash);

  static std::optional<Scan> getById(
      const drogon::orm::DbClientPtr &dbClient, const std::string &id);

  static void create(const drogon::orm::DbClientPtr &dbClient,
                     Scan &scan);

  static void update(const drogon::orm::DbClientPtr &dbClient,
                     Scan &scan);

  [[nodiscard]] const std::string &getId() const {
    return m_id;
  }

  [[nodiscard]] const std::string &getFileHash() const {
    return m_fileHash;
  }

  [[nodiscard]] ScanStatus getStatus() const {
    return m_status;
  }

  [[nodiscard]] VirusType getVirusType() const {
    return m_virusType;
  }

  [[nodiscard]] const double &getScore() const {
    return m_score;
  }

  [[nodiscard]] int getRuntime() const {
    return m_runtime;
  }

  [[nodiscard]] const trantor::Date &getCreatedAt() const {
    return m_createdAt;
  }

  [[nodiscard]] const trantor::Date &getUpdatedAt() const {
    return m_updatedAt;
  }

  void setId(const std::string &id) {
    m_id = id;
  }

  void setFileHash(const std::string &fileHash) {
    m_fileHash.clear();
    m_fileHash.assign(fileHash.data(), fileHash.length());
  }

  void setStatus(ScanStatus status) {
    m_status = status;
  }

  void setVirusType(VirusType virusType) {
    m_virusType = virusType;
  }

  void setScore(const double &score) {
    m_score = score;
  }

  void setRuntime(int runtime) {
    m_runtime = runtime;
  }

  void setCreatedAt(const trantor::Date &createdAt) {
    m_createdAt = createdAt;
  }

  void setUpdatedAt(const trantor::Date &updatedAt) {
    m_updatedAt = updatedAt;
  }

private:
};
} // namespace Models
