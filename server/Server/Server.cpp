#include <iostream>
#include <string>
#include <string_view>

#include <drogon/HttpAppFramework.h>
#include <trantor/utils/Logger.h>

#include "Constants.hpp"
#include "Controllers/Auth.hpp"
#include "Controllers/Sandbox.hpp"
#include "DatabaseSetup.hpp"
#include "Utils/SandboxRuntimeConfig.hpp"

int main(int argc, char *argv[]) {
  if (argc == 2 && std::string_view(argv[1]) == "--self-test") {
    std::string failure;
    if (Utils::SandboxRuntimeConfig::runSelfTests(&failure)) {
      std::cout << "[self-test] PASS sandbox_runtime_config" << std::endl;
      return EXIT_SUCCESS;
    }

    std::cerr << "[self-test] FAIL sandbox_runtime_config: " << failure
              << std::endl;
    return EXIT_FAILURE;
  }

  // Setup the server
  drogon::app()
      .loadConfigFile(std::string(Constants::CONFIG_FILE));

  // Configure maximum upload size (default 50MB, overridable via config.json)
  {
    constexpr std::size_t DEFAULT_MAX_UPDATE_SIZE_BYTES = 50 * 1024 * 1024; // 50MiB
    const auto &customCfg = drogon::app().getCustomConfig();

    Json::UInt64 maxUploadBytes = DEFAULT_MAX_UPDATE_SIZE_BYTES;
    const auto key = Constants::MAX_UPLOAD_BYTES_KEY.data();

    if (customCfg.isMember(key)) {
      const auto &val = customCfg[key];

      if (val.isUInt64()) {
        maxUploadBytes = val.asUInt64();
      } else if (val.isUInt()) {
        maxUploadBytes = val.asUInt();
      } else if (val.isInt64()) {
        const auto tmp = val.asInt64();
        if (tmp > 0) {
          maxUploadBytes = static_cast<Json::UInt64>(tmp);
        }
      }
    }

    drogon::app().setClientMaxBodySize(static_cast<std::size_t>(maxUploadBytes));
  }

  // Setup the database and make sure we have a JWT secret
  drogon::app().registerBeginningAdvice([]() {
    if (!DatabaseSetup::setupDatabase()) {
      exit(EXIT_FAILURE);
    }

    auto jwtSecret = drogon::app().getCustomConfig().get(Constants::JWT_SECRET_JSON_KEY.data(), "");

    if (jwtSecret.empty()) {
      LOG_ERROR << "No JWT secret found in config! Please add it to the config file.";

      exit(EXIT_FAILURE);
    }
  });

  LOG_INFO << "Starting server with config from " << Constants::CONFIG_FILE;

  drogon::app().run();

  return EXIT_SUCCESS;
}
