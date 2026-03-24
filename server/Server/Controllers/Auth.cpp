#include "Auth.hpp"

#include <drogon/HttpResponse.h>
#include <drogon/HttpTypes.h>

#include "../Constants.hpp"
#include "../JWT.hpp"
#include "../Models/User.hpp"
#include "../Utils/Generic.hpp"
#include "../Utils/Password.hpp"
#include "../Utils/Responses.hpp"
#include "../Utils/Validation.hpp"

void API::Auth::_registerUser(
    const drogon::HttpRequestPtr &req,
    std::function<void(const drogon::HttpResponsePtr &)> &&callback) {
  LOG_DEBUG << "Got a register user request";

  constexpr const char *WEAK_PASSWORD_MESSAGE =
      "Password is too weak (minimum 8 characters, with upper, lower, and digit).";

  auto jsonBody = req->getJsonObject();

  if (!jsonBody) {
    return callback(jsonError("Invalid JSON"));
  }

  std::string rawPassword;
  if (jsonBody->isMember("password") && (*jsonBody)["password"].isString()) {
    rawPassword = (*jsonBody)["password"].asString();
  }

  if (!rawPassword.empty() && !Utils::Validation::isValidPassword(rawPassword)) {
    return callback(jsonError(WEAK_PASSWORD_MESSAGE));
  }

  auto email = Utils::Validation::validateField(
      jsonBody.get(), "email", Utils::Validation::FieldType::Email);
  auto nickname = Utils::Validation::validateField(
      jsonBody.get(), "nickname", Utils::Validation::FieldType::Nickname);
  auto password = Utils::Validation::validateField(
      jsonBody.get(), "password", Utils::Validation::FieldType::Password);

  if (!email || !nickname || !password) {
    return callback(jsonError("Invalid or missing fields"));
  }

  try {
    auto dbClient = drogon::app().getDbClient();

    const auto existingUser = Models::User::getByEmail(dbClient, *email);

    if (existingUser.has_value()) {
      return callback(jsonError("User with this email already exists",
                                drogon::HttpStatusCode::k409Conflict));
    }

    const auto passwordHash = Utils::Password::hash(*password);

    Models::User newUser;
    newUser.setEmail(*email);
    newUser.setNickname(*nickname);
    newUser.setPasswordHash(passwordHash);

    Models::User::create(dbClient, newUser);

    const auto [accessToken, refreshToken] = generateTokenPair(newUser.getId());

    Json::Value resp;
    resp["message"] = "User created";
    resp["accessToken"] = accessToken;
    resp["refreshToken"] = refreshToken;

    return callback(jsonOk(resp));
  } catch (const std::exception &e) {
    return callback(jsonError(std::string("Internal server error: ") + e.what(),
                              drogon::HttpStatusCode::k500InternalServerError));
  }
}

void API::Auth::_loginUser(const drogon::HttpRequestPtr &req,
                           std::function<void(const drogon::HttpResponsePtr &)> &&callback) {
  LOG_DEBUG << "Got a login user request";

  constexpr const char *WEAK_PASSWORD_MESSAGE =
      "Password is too weak (minimum 8 characters, with upper, lower, and digit).";

  auto jsonBody = req->getJsonObject();

  if (!jsonBody) {
    return callback(jsonError("Invalid JSON"));
  }

  std::string rawPassword;
  if (jsonBody->isMember("password") && (*jsonBody)["password"].isString()) {
    rawPassword = (*jsonBody)["password"].asString();
  }

  if (!rawPassword.empty() && !Utils::Validation::isValidPassword(rawPassword)) {
    return callback(jsonError(WEAK_PASSWORD_MESSAGE));
  }

  auto email = Utils::Validation::validateField(
      jsonBody.get(), "email", Utils::Validation::FieldType::Email);
  auto password = Utils::Validation::validateField(
      jsonBody.get(), "password", Utils::Validation::FieldType::Password);

  if (!email || !password) {
    return callback(jsonError("Invalid or missing fields"));
  }

  auto dbUser = Models::User::getByEmail(drogon::app().getDbClient(), *email);

  if (!dbUser.has_value()) {
    return callback(jsonError("Invalid email or password!",
                              drogon::HttpStatusCode::k401Unauthorized));
  }

  if (!Utils::Password::verify(*password, dbUser->getPasswordHash())) {
    return callback(jsonError("Invalid email or password!",
                              drogon::HttpStatusCode::k401Unauthorized));
  }

  auto [accessToken, refreshToken] = generateTokenPair(dbUser->getId());

  Json::Value resp;
  resp["message"] = "User logged in";
  resp["accessToken"] = accessToken;
  resp["refreshToken"] = refreshToken;

  return callback(jsonOk(resp));
}

void API::Auth::_refreshToken(const drogon::HttpRequestPtr &req,
                              std::function<void(const drogon::HttpResponsePtr &)> &&callback) {
  LOG_DEBUG << "Got a refresh token request";

  auto jsonBody = req->getJsonObject();

  if (!jsonBody) {
    return callback(jsonError("Invalid JSON"));
  }

  auto refreshToken = Utils::Validation::validateField(
      jsonBody.get(), "refreshToken", Utils::Validation::FieldType::RefreshToken);

  if (!refreshToken) {
    return callback(jsonError("Invalid or missing fields"));
  }

  // Verify the refresh token
  auto claims = JWT::verify(*refreshToken);
  if (!claims) {
    return callback(jsonError("Invalid or expired refresh token",
                              drogon::HttpStatusCode::k401Unauthorized));
  }

  // Check if it's a refresh token
  auto typeIt = claims->find("type");
  if (typeIt == claims->end() || typeIt->second != "refresh") {
    return callback(jsonError("Invalid token type",
                              drogon::HttpStatusCode::k401Unauthorized));
  }

  // Get user ID from token
  auto subIt = claims->find("sub");
  if (subIt == claims->end()) {
    return callback(jsonError("Invalid token",
                              drogon::HttpStatusCode::k401Unauthorized));
  }
  std::string userId = subIt->second;

  // Check expiration
  auto expIt = claims->find("exp");
  if (expIt != claims->end()) {
    try {
      long long exp = std::stoll(expIt->second);
      auto now = Utils::Generic::getCurrentTimestamp();
      if (exp < now) {
        return callback(jsonError("Token expired",
                                  drogon::HttpStatusCode::k401Unauthorized));
      }
    } catch (...) {
      return callback(jsonError("Invalid token",
                                drogon::HttpStatusCode::k401Unauthorized));
    }
  }

  // Generate a new access token
  const auto [accessToken, _] = generateTokenPair(userId);

  Json::Value resp;
  resp["accessToken"] = accessToken;
  callback(jsonOk(resp));
}

void API::Auth::_getMe(const drogon::HttpRequestPtr &req,
                       std::function<void(const drogon::HttpResponsePtr &)> &&callback) {
  LOG_DEBUG << "Got a get me request";

  // Get user ID from request attributes (set by AuthMiddleware)
  auto userId = req->attributes()->get<std::string>("userId");

  if (userId.empty()) {
    return callback(jsonError("Unauthorized",
                              drogon::HttpStatusCode::k401Unauthorized));
  }

  try {
    auto dbClient = drogon::app().getDbClient();
    auto user = Models::User::getById(dbClient, userId);

    if (!user.has_value()) {
      return callback(jsonError("User not found",
                                drogon::HttpStatusCode::k404NotFound));
    }

    Json::Value resp;
    resp["email"] = user->getEmail();
    resp["nickname"] = user->getNickname();

    callback(jsonOk(resp));
  } catch (const std::exception &e) {
    return callback(jsonError(std::string("Internal server error: ") + e.what(),
                              drogon::HttpStatusCode::k500InternalServerError));
  }
}

// Generate a pair of access and refresh tokens
std::pair<std::string, std::string> API::Auth::generateTokenPair(const std::string &userId) {
  const auto now = Utils::Generic::getCurrentTimestamp();
  const auto accessExp = now + Constants::ACCESS_TOKEN_TTL_SECONDS;
  const auto refreshExp = now + Constants::REFRESH_TOKEN_TTL_SECONDS;

  // Generate access token
  JWT::Claims accessClaims = {
      {"sub", userId},
      {"exp", std::to_string(accessExp)},
      {"type", "access"}};
  std::string accessToken = JWT::generate(accessClaims);

  // Generate refresh token
  JWT::Claims refreshClaims = {
      {"sub", userId},
      {"exp", std::to_string(refreshExp)},
      {"type", "refresh"}};
  std::string refreshToken = JWT::generate(refreshClaims);

  return {accessToken, refreshToken};
}