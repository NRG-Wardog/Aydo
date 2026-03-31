#pragma once

#include <string>

// Default config values
class UserConfig {
public:
  int killThreshold = 150;
  double entropyThreshold = 7.0;
  std::string serverUrl = "http://192.168.56.1";
  std::string accessToken;
  std::string refreshToken;
  int runtime = 60;
  int infectedFileAction = 0; // 0=None, 1=Quarantine, 2=Delete
  int dynamicScanThreshold = 25;
  unsigned long long maxScanSize = 500 * 1024 * 1024; // 500MB default

  static UserConfig &getInstance();
  bool load(const std::string &configPath = "config.json");
  bool save(const std::string &configPath = "config.json") const;

private:
  UserConfig() = default;
};
