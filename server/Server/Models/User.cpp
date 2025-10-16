#include "User.hpp"

#include <drogon/drogon.h>
#include <drogon/orm/DbClient.h>
#include <optional>

namespace Models {

using drogon::orm::DbClientPtr;

User::User(const drogon::orm::Row &row) {
  try {
    m_id = std::to_string(row["id"].as<int>());
    m_email = row["email"].as<std::string>();
    m_nickname = row["nickname"].as<std::string>();
    m_passwordHash = row["passwordHash"].as<std::string>();
  } catch (const std::exception &e) {
    LOG_WARN << "Failed to parse User from row: " << e.what();
  } catch (...) {
    LOG_WARN << "Failed to parse User from row: unknown error";
  }
}

std::optional<User> User::getByEmail(const DbClientPtr &dbClient,
                                     const std::string &email) {
  if (email.empty()) {
    return std::nullopt;
  }

  auto result = dbClient->execSqlSync(
      "SELECT id, email, nickname, passwordHash FROM users WHERE email = $1 LIMIT 1",
      email);

  if (result.empty()) {
    return std::nullopt;
  }

  const auto &row = result[0];

  User user(row);

  return user;
}

std::optional<User> User::getById(const DbClientPtr &dbClient,
                                  const std::string &id) {
  if (id.empty()) {
    return std::nullopt;
  }

  int userId;
  try {
    userId = std::stoi(id);
  } catch (...) {
    return std::nullopt;
  }

  auto result = dbClient->execSqlSync(
      "SELECT id, email, nickname, passwordHash, createdAt, updatedAt FROM users WHERE id = $1 LIMIT 1",
      userId);

  if (result.empty()) {
    return std::nullopt;
  }

  const auto &row = result[0];

  User user(row);

  return user;
}

void User::create(const DbClientPtr &dbClient, User &user) {
  auto result = dbClient->execSqlSync(
      "INSERT INTO users (email, nickname, passwordHash) VALUES ($1, $2, $3) RETURNING id",
      user.getEmail(), user.getNickname(), user.getPasswordHash());

  if (!result.empty()) {
    user.setId(std::to_string(result[0]["id"].as<int>()));
  }
}

} // namespace Models
