#pragma once

#include <json/json.h>
#include <optional>
#include <regex>
#include <string>

namespace Utils::Validation {

enum class FieldType {
  Email,
  Nickname,
  Password,
  RefreshToken,
  FileHash,
  Runtime
};

inline constexpr unsigned int MIN_PASSWORD_LENGTH = 8;
inline const std::regex EMAIL_PATTERN(
    R"(^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$)" // RFC 5322
);
inline const std::regex NICKNAME_PATTERN(R"(^[a-zA-Z]+$)");
inline const std::regex PASSWORD_HAS_ATLEAST_ONE_LOWER(R"([a-z])");
inline const std::regex PASSWORD_HAS_ATLEAST_ONE_UPPER(R"([A-Z])");
inline const std::regex PASSWORD_HAS_ATLEAST_ONE_DIGIT(R"([0-9])");
inline const size_t SHA256_HEX_LENGTH = 64;
inline const size_t MIN_RUNTIME_SECONDS = 60;
inline const size_t MAX_RUNTIME_SECONDS = 60 * 5;

[[nodiscard]] std::optional<std::string> validateField(
    const Json::Value *jsonBody,
    const std::string &fieldName,
    FieldType fieldType);

[[nodiscard]] bool isValidEmail(const std::string &email);

[[nodiscard]] bool isValidNickname(const std::string &nickname);

[[nodiscard]] bool isValidPassword(const std::string &password);

[[nodiscard]] bool isValidRefreshToken(std::string_view refreshToken);

[[nodiscard]] bool isValidFileHash(const std::string &fileHash);

[[nodiscard]] bool isValidRuntime(const std::string &runtime);

} // namespace Utils::Validation
