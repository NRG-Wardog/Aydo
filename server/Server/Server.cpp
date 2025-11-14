#include <drogon/HttpAppFramework.h>
#include <trantor/utils/Logger.h>

#include "Constants.hpp"
#include "Controllers/Auth.hpp"
#include "Controllers/Sandbox.hpp"
#include "DatabaseSetup.hpp"

int main() {
  // Setup the server
  drogon::app()
      .loadConfigFile(std::string(Constants::CONFIG_FILE));

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
