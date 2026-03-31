#include "User.hpp"

#include <drogon/drogon.h>
#include <drogon/orm/DbClient.h>
#include <optional>

using drogon::orm::DbClientPtr;

namespace Models {

User::User(const drogon::orm::Row &row) {
  try {
    m_id = std::to_string(row["id"].as<int>());
    m_email = row["email"].as<std::string>();
    m_nickname = row["nickname"].as<std::string>();
    m_passwordHash = row["passwordHash"].as<std::string>();
    m_createdAt =
        trantor::Date::fromDbString(row["createdAt"].as<std::string>());
    m_updatedAt =
        trantor::Date::fromDbString(row["updatedAt"].as<std::string>());
  } catch (const std::exception &e) {
    LOG_WARN << "Failed to parse User from row: " << e.what();
  } catch (...) {
    LOG_WARN << "Failed to parse User from row: unknown error";
  }
}

std::optional<User> User::getByEmail(const DbClientPtr &dbClient,
                                     const std::string &email) {
  try {
    auto result = dbClient->execSqlSync(
        "SELECT id, email, nickname, passwordHash, createdAt, updatedAt FROM users WHERE email = $1 LIMIT 1",
        email);

    if (result.empty()) {
      return std::nullopt;
    }

    const auto &row = result[0];

    User user(row);

    return user;
  } catch (const drogon::orm::DrogonDbException &e) {
    LOG_ERROR << "Database error in User::getByEmail: " << e.base().what();
  } catch (const std::exception &e) {
    LOG_ERROR << "Unexpected error in User::getByEmail: " << e.what();
  } catch (...) {
    LOG_ERROR << "Unexpected unknown error in User::getByEmail";
  }

  return std::nullopt;
}

std::optional<User> User::getById(const DbClientPtr &dbClient,
                                  const std::string &id) {
  // Validate and convert string ID to integer for database query
  if (id.empty()) {
    return std::nullopt;
  }

  int userId;
  try {
    userId = std::stoi(id);
  } catch (...) {
    return std::nullopt;
  }

  try {
    auto result = dbClient->execSqlSync(
        "SELECT id, email, nickname, passwordHash, createdAt, updatedAt FROM users WHERE id = $1 LIMIT 1",
        userId);

    if (result.empty()) {
      return std::nullopt;
    }

    const auto &row = result[0];

    User user(row);

    return user;
  } catch (const drogon::orm::DrogonDbException &e) {
    LOG_ERROR << "Database error in User::getById: " << e.base().what();
  } catch (const std::exception &e) {
    LOG_ERROR << "Unexpected error in User::getById: " << e.what();
  } catch (...) {
    LOG_ERROR << "Unexpected unknown error in User::getById";
  }

  return std::nullopt;
}

void User::create(const DbClientPtr &dbClient, User &user) {
  try {
    auto result = dbClient->execSqlSync(
        "INSERT INTO users (email, nickname, passwordHash) VALUES ($1, $2, $3) RETURNING id",
        user.getEmail(), user.getNickname(), user.getPasswordHash());

    if (!result.empty()) {
      user.setId(std::to_string(result[0]["id"].as<int>()));
    }
  } catch (const drogon::orm::DrogonDbException &e) {
    LOG_ERROR << "Database error in User::create: " << e.base().what();
  } catch (const std::exception &e) {
    LOG_ERROR << "Unexpected error in User::create: " << e.what();
  } catch (...) {
    LOG_ERROR << "Unexpected unknown error in User::create";
  }
}

} // namespace Models
