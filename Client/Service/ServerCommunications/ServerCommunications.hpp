#pragma once

#include <atomic>
#include <memory>
#include <mutex>
#include <nlohmann/json.hpp>
#include <string>
#include <thread>

class ServerCommunications {
private:
  std::string m_serverAddress;
  std::string m_authenticationToken;
  std::string m_refreshToken;

  std::atomic<bool> m_serverReachable{false};
  std::atomic<bool> m_stopReachability{false};
  std::thread m_reachabilityThread;

  static std::unique_ptr<ServerCommunications> m_instance;
  static std::mutex m_mutex;

  ServerCommunications(const std::string &serverAddress,
                       const std::string &authenticationToken,
                       const std::string &refreshToken = "");

  enum class HttpStatus {
    Ok = 200,
    Created = 201,
    BadRequest = 400,
    Unauthorized = 401,
    Forbidden = 403,
    NotFound = 404,
    Conflict = 409,
    InternalServerError = 500
  };

  long postRequest(const std::string &endpoint, const std::string &body, std::string &responseBody);
  bool refreshToken();
  void startReachabilityMonitor();
  void stopReachabilityMonitor();
  [[nodiscard]] bool pingServer() const;

public:
  ~ServerCommunications();

  ServerCommunications(const ServerCommunications &) = delete;
  ServerCommunications &operator=(const ServerCommunications &) = delete;
  ServerCommunications(ServerCommunications &&) = delete;
  ServerCommunications &operator=(ServerCommunications &&) = delete;

  static void initialize(const std::string &serverAddress, const std::string &authenticationToken = "", const std::string &refreshToken = "");
  static ServerCommunications &getInstance();

  void updateConnectionSettings(const std::string &serverAddress,
                                const std::string &authenticationToken,
                                const std::string &refreshToken);

  [[nodiscard]] bool isServerReachable() const;

  bool login(const std::string &email, const std::string &password);
  bool registerUser(const std::string &email, const std::string &nickname, const std::string &password);

  bool requestFileScan(const std::string &fileHash, int runtime, nlohmann::json &responseJson);
  bool uploadFile(const std::string &fileHash, const std::string &filePath);
};
