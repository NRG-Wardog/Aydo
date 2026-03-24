#include "ServerCommunications.hpp"
#include "../Constants.hpp"
#include "../UserConfig.hpp"

#include <cpr/cpr.h>
#include <iostream>
#include <nlohmann/json.hpp>
#include <thread>

std::unique_ptr<ServerCommunications> ServerCommunications::m_instance = nullptr;
std::mutex ServerCommunications::m_mutex;

void ServerCommunications::initialize(const std::string &serverAddress, const std::string &authenticationToken, const std::string &refreshToken) {
  std::lock_guard<std::mutex> lock(m_mutex);
  if (!m_instance) {
    m_instance.reset(new ServerCommunications(serverAddress, authenticationToken, refreshToken));
    m_instance->startReachabilityMonitor();
  } else {
    m_instance->updateConnectionSettings(serverAddress, authenticationToken, refreshToken);
  }
}

bool ServerCommunications::isServerReachable() const {
  return m_serverReachable.load(std::memory_order_relaxed);
}

ServerCommunications &ServerCommunications::getInstance() {
  std::lock_guard<std::mutex> lock(m_mutex);
  if (!m_instance) {
    throw std::runtime_error("ServerCommunications not initialized. Call initialize() first.");
  }
  return *m_instance;
}

ServerCommunications::ServerCommunications(const std::string &serverAddress,
                                           const std::string &authenticationToken,
                                           const std::string &refreshToken)
    : m_serverAddress(serverAddress)
    , m_authenticationToken(authenticationToken)
    , m_refreshToken(refreshToken) {}

ServerCommunications::~ServerCommunications() {
  stopReachabilityMonitor();
}

void ServerCommunications::updateConnectionSettings(const std::string &serverAddress,
                                                    const std::string &authenticationToken,
                                                    const std::string &refreshToken) {
  m_serverAddress = serverAddress;
  m_authenticationToken = authenticationToken;
  m_refreshToken = refreshToken;
  m_serverReachable.store(pingServer(), std::memory_order_relaxed);
}

void ServerCommunications::startReachabilityMonitor() {
  if (m_reachabilityThread.joinable()) {
    return;
  }

  m_stopReachability.store(false, std::memory_order_relaxed);
  m_reachabilityThread = std::thread([this]() {
    while (!m_stopReachability.load(std::memory_order_relaxed)) {
      const bool reachable = pingServer();
      m_serverReachable.store(reachable, std::memory_order_relaxed);
      std::this_thread::sleep_for(Constants::SERVER_REACHABILITY_POLL_INTERVAL);
    }
  });
}

void ServerCommunications::stopReachabilityMonitor() {
  m_stopReachability.store(true, std::memory_order_relaxed);
  if (m_reachabilityThread.joinable()) {
    m_reachabilityThread.join();
  }
}

bool ServerCommunications::pingServer() const {
  if (m_serverAddress.empty()) {
    return false;
  }

  try {
    cpr::Header headers;
    if (!m_authenticationToken.empty()) {
      headers.insert({"Authorization", "Bearer " + m_authenticationToken});
    }

    const auto response = cpr::Get(
        cpr::Url{m_serverAddress + "/api/health"},
        headers,
        cpr::Timeout{Constants::REQUEST_TIMEOUT_DURATION});

    // Any HTTP response code other than 0 means the server is reachable even if the endpoint is missing
    return response.status_code >= 200 && response.status_code < 500;
  } catch (const std::exception &e) {
    std::cerr << "Ping error: " << e.what() << std::endl;
    return false;
  }
}

long ServerCommunications::postRequest(const std::string &endpoint, const std::string &body, std::string &responseBody) {
  auto performRequest = [&]() -> long {
    try {
      cpr::Header headers = {{"Content-Type", "application/json"}};
      if (!m_authenticationToken.empty()) {
        headers.insert({"Authorization", "Bearer " + m_authenticationToken});
      }

      auto response = cpr::Post(
          cpr::Url{m_serverAddress + endpoint},
          cpr::Body{body},
          headers,
          cpr::Timeout{Constants::REQUEST_TIMEOUT_DURATION});

      responseBody = response.text;
      return response.status_code;
    } catch (const std::exception &e) {
      std::cerr << "Request error on " << endpoint << ": " << e.what() << std::endl;
      return 0;
    }
  };

  long status = performRequest();

  // If unauthorized and not a login/register/refresh request, try to refresh token and retry
  // or return -1 if the refresh token is empty
  if (status == static_cast<long>(HttpStatus::Unauthorized) &&
      endpoint != "/api/auth/login" &&
      endpoint != "/api/auth/register" &&
      endpoint != "/api/auth/refresh-token") {
    if (m_refreshToken == "") {
      std::cout << "Skipping request because refresh token is empty" << std::endl;

      return -1;
    }

    if (refreshToken()) {
      status = performRequest();
    }
  }

  return status;
}

bool ServerCommunications::refreshToken() {
  if (m_refreshToken.empty()) {
    return false;
  }

  nlohmann::json payload = {{"refreshToken", m_refreshToken}};
  std::string responseBody;

  try {
    auto response = cpr::Post(
        cpr::Url{m_serverAddress + "/api/auth/refresh-token"},
        cpr::Body{payload.dump()},
        cpr::Header{{"Content-Type", "application/json"}},
        cpr::Timeout{Constants::REQUEST_TIMEOUT_DURATION});

    if (response.status_code == static_cast<long>(HttpStatus::Ok)) {
      auto jsonResponse = nlohmann::json::parse(response.text);
      if (jsonResponse.contains("accessToken")) {
        m_authenticationToken = jsonResponse["accessToken"];
        UserConfig::getInstance().accessToken = m_authenticationToken;
        UserConfig::getInstance().save();
        return true;
      }
    }
  } catch (const std::exception &e) {
    std::cerr << "Refresh token error: " << e.what() << std::endl;
  }

  return false;
}

bool ServerCommunications::login(const std::string &email, const std::string &password) {
  nlohmann::json payload = {
      {"email", email},
      {"password", password}};

  std::string responseBody;
  if (postRequest("/api/auth/login", payload.dump(), responseBody) == static_cast<long>(HttpStatus::Ok)) {
    try {
      auto jsonResponse = nlohmann::json::parse(responseBody);
      if (jsonResponse.contains("accessToken")) {
        m_authenticationToken = jsonResponse["accessToken"];
        UserConfig::getInstance().accessToken = m_authenticationToken;
        if (jsonResponse.contains("refreshToken")) {
          m_refreshToken = jsonResponse["refreshToken"];
          UserConfig::getInstance().refreshToken = m_refreshToken;
        }
        UserConfig::getInstance().save();
        return true;
      }
    } catch (const std::exception &e) {
      std::cerr << "Login JSON parse error: " << e.what() << std::endl;
    }
  }
  return false;
}

bool ServerCommunications::registerUser(const std::string &email, const std::string &nickname, const std::string &password) {
  nlohmann::json payload = {
      {"email", email},
      {"nickname", nickname},
      {"password", password}};

  std::string responseBody;
  if (postRequest("/api/auth/register", payload.dump(), responseBody) == static_cast<long>(HttpStatus::Ok)) {
    try {
      auto jsonResponse = nlohmann::json::parse(responseBody);
      if (jsonResponse.contains("accessToken")) {
        m_authenticationToken = jsonResponse["accessToken"];
        UserConfig::getInstance().accessToken = m_authenticationToken;
        if (jsonResponse.contains("refreshToken")) {
          m_refreshToken = jsonResponse["refreshToken"];
          UserConfig::getInstance().refreshToken = m_refreshToken;
        }
        UserConfig::getInstance().save();
        return true;
      }
    } catch (const std::exception &e) {
      std::cerr << "Register JSON parse error: " << e.what() << std::endl;
    }
  }
  return false;
}

bool ServerCommunications::requestFileScan(const std::string &fileHash, const int runtime, nlohmann::json &responseJson) {
  nlohmann::json payload = {
      {"fileHash", fileHash},
      {"runtime", std::to_string(runtime)}};

  std::string responseBody;
  long status = postRequest("/api/sandbox/request-file-scan", payload.dump(), responseBody);
  if (status == static_cast<long>(HttpStatus::Ok) || status == static_cast<long>(HttpStatus::Created)) {
    try {
      responseJson = nlohmann::json::parse(responseBody);
      return true;
    } catch (const std::exception &e) {
      std::cerr << "RequestFileScan JSON parse error: " << e.what() << std::endl;
    }
  }

  return false;
}

bool ServerCommunications::uploadFile(const std::string &fileHash, const std::string &filePath) {
  auto performUpload = [&]() -> long {
    try {
      cpr::Header headers;
      if (!m_authenticationToken.empty()) {
        headers.insert({"Authorization", "Bearer " + m_authenticationToken});
      }

      auto response = cpr::Post(
          cpr::Url{m_serverAddress + "/api/sandbox/upload-file"},
          cpr::Multipart{{"fileHash", fileHash},
                         {"file", cpr::File{filePath}}},
          headers,
          cpr::Timeout{Constants::REQUEST_TIMEOUT_DURATION});

      return response.status_code;
    } catch (const std::exception &e) {
      std::cerr << "UploadFile error: " << e.what() << std::endl;
      return 0;
    }
  };

  long status = performUpload();

  if (status == static_cast<long>(HttpStatus::Unauthorized)) {
    if (refreshToken()) {
      status = performUpload();
    }
  }

  return status == static_cast<long>(HttpStatus::Ok);
}
