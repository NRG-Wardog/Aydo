#include "UserConfig.hpp"

#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>

UserConfig &UserConfig::getInstance() {
  static UserConfig instance;
  return instance;
}

bool UserConfig::load(const std::string &configPath) {
  std::ifstream file(configPath);
  if (!file.is_open()) {
    std::cerr << "Warning: Could not open config file " << configPath << ". Using defaults." << std::endl;
    return false;
  }

  try {
    nlohmann::json j;
    file >> j;

    if (j.contains("killThreshold")) {
      killThreshold = j["killThreshold"];
    }
    if (j.contains("serverUrl")) {
      serverUrl = j["serverUrl"];
    }
    if (j.contains("accessToken")) {
      accessToken = j["accessToken"];
    }
    if (j.contains("refreshToken")) {
      refreshToken = j["refreshToken"];
    }
    if (j.contains("runtime")) {
      runtime = j["runtime"];
    }
    if (j.contains("entropyThreshold")) {
      entropyThreshold = j["entropyThreshold"];
    }
    if (j.contains("infectedFileAction")) {
      infectedFileAction = j["infectedFileAction"];
    }
    if (j.contains("dynamicScanThreshold")) {
      dynamicScanThreshold = j["dynamicScanThreshold"];
    }
    if (j.contains("maxScanSize")) {
      maxScanSize = j["maxScanSize"];
    }

    return true;
  } catch (const std::exception &e) {
    std::cerr << "Error parsing config file: " << e.what() << std::endl;
    return false;
  }
}


bool UserConfig::save(const std::string &configPath) const {
  try {
    nlohmann::json j;
    j["killThreshold"] = killThreshold;
    j["serverUrl"] = serverUrl;
    j["accessToken"] = accessToken;
    j["refreshToken"] = refreshToken;
    j["runtime"] = runtime;
    j["entropyThreshold"] = entropyThreshold;

    std::ofstream file(configPath);
    if (!file.is_open()) {
      return false;
    }

    file << j.dump();
    return true;
  } catch (const std::exception &e) {
    std::cerr << "Error saving config file: " << e.what() << std::endl;
    return false;
  }
}
