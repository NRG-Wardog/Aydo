#pragma once
#include <drogon/HttpAppFramework.h>
#include <string>
#include <trantor/utils/Logger.h>

namespace DatabaseSetup {

bool makeSureUserTableExists(const drogon::orm::DbClientPtr &dbClient);
bool makeSureScansTableExists(const drogon::orm::DbClientPtr &dbClient);

bool setupDatabase();

} // namespace DatabaseSetup
