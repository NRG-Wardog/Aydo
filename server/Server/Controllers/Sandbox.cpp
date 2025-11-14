#include "Sandbox.hpp"

#include "../Constants.hpp"
#include "../Models/Scan.hpp"
#include "../Utils/Generic.hpp"
#include "../Utils/Responses.hpp"
#include "../Utils/VM.hpp"
#include "../Utils/Validation.hpp"
#include "drogon/MultiPart.h"
#include "trantor/utils/Logger.h"

void API::Sandbox::_requestFileScan(const drogon::HttpRequestPtr &req,
                                    std::function<void(const drogon::HttpResponsePtr &)> &&callback) {
  LOG_DEBUG << "Got a request file scan request";

  auto jsonBody = req->getJsonObject();

  if (!jsonBody) {
    return callback(jsonError("Invalid JSON"));
  }

  auto fileHash = Utils::Validation::validateField(
      jsonBody.get(), "fileHash", Utils::Validation::FieldType::FileHash);
  auto runtime = Utils::Validation::validateField(
      jsonBody.get(), "runtime", Utils::Validation::FieldType::Runtime);

  if (!fileHash || !runtime) {
    return callback(jsonError("Invalid or missing fields"));
  }

  try {
    auto dbClient = drogon::app().getDbClient();

    const auto existingScan = Models::Scan::getByFileHash(dbClient, *fileHash);

    if (existingScan.has_value()) {
      Json::Value response;
      response["status"] = static_cast<int>(existingScan->getStatus());
      response["virusType"] = static_cast<int>(existingScan->getVirusType());
      response["runtime"] = existingScan->getRuntime();
      response["score"] = existingScan->getScore();

      auto resp = drogon::HttpResponse::newHttpJsonResponse(response);
      resp->setStatusCode(drogon::HttpStatusCode::k200OK);

      return callback(resp);
    }

    Models::Scan newScan;
    newScan.setFileHash(*fileHash);
    newScan.setStatus(Models::ScanStatus::Pending);
    newScan.setVirusType(Models::VirusType::Clean);
    newScan.setRuntime(std::stoi(*runtime));
    newScan.setScore(0.0);

    Models::Scan::create(dbClient, newScan);

    return callback(jsonOk("Scan requested successfully"));
  } catch (const std::exception &e) {
    return callback(jsonError(std::string("Internal server error: ") + e.what(),
                              drogon::HttpStatusCode::k500InternalServerError));
  }
}

void API::Sandbox::_uploadFile(const drogon::HttpRequestPtr &req,
                               std::function<void(const drogon::HttpResponsePtr &)> &&callback) {
  LOG_DEBUG << "Got an upload file request";

  auto jsonBody = req->getJsonObject();

  if (!jsonBody) {
    return callback(jsonError("Invalid JSON"));
  }

  auto fileHash = Utils::Validation::validateField(
      jsonBody.get(), "fileHash", Utils::Validation::FieldType::FileHash);

  if (!fileHash) {
    return callback(jsonError("Invalid or missing fields"));
  }

  drogon::MultiPartParser parser;
  // Allow only one file, that is
  if (!parser.parse(req) || parser.getFiles().size() != 1) {
    return callback(jsonError("Invalid or missing file"));
  }

  try {
    auto dbClient = drogon::app().getDbClient();

    auto existingScan = Models::Scan::getByFileHash(dbClient, *fileHash);

    if (!existingScan.has_value()) {
      return callback(jsonError("Scan not found", drogon::HttpStatusCode::k404NotFound));
    }

    auto &file = parser.getFiles()[0];

    std::string filePath = Utils::Generic::getScanSavePathForFileHash(*fileHash);
    file.saveAs(filePath);

    if (!Utils::VM::startVM(existingScan->getId(), filePath, existingScan->getRuntime())) {
      return callback(jsonError("Failed to start VM"));
    }

    existingScan->setStatus(Models::ScanStatus::InProgress);
    Models::Scan::update(dbClient, existingScan.value());

    return callback(jsonOk("File uploaded successfully"));
  } catch (const std::exception &e) {
    return callback(jsonError(std::string("Internal server error: ") + e.what(),
                              drogon::HttpStatusCode::k500InternalServerError));
  }
}

void API::Sandbox::_getScan(const drogon::HttpRequestPtr &req,
                            std::function<void(const drogon::HttpResponsePtr &)> &&callback) {
  LOG_DEBUG << "Got a get scan request";

  auto jsonBody = req->getJsonObject();

  if (!jsonBody) {
    return callback(jsonError("Invalid JSON"));
  }

  auto fileHash = Utils::Validation::validateField(
      jsonBody.get(), "fileHash", Utils::Validation::FieldType::FileHash);

  if (!fileHash) {
    return callback(jsonError("Invalid or missing fields"));
  }

  try {
    auto dbClient = drogon::app().getDbClient();

    const auto existingScan = Models::Scan::getByFileHash(dbClient, *fileHash);

    if (!existingScan.has_value()) {
      return callback(jsonError("Scan not found", drogon::HttpStatusCode::k404NotFound));
    }

    // Check if the buffer time have passed since updatedAt (when VM started)
    auto now = trantor::Date::now();
    auto scanUpdatedTime = existingScan->getUpdatedAt();
    auto elapsedSeconds = now.secondsSinceEpoch() - scanUpdatedTime.secondsSinceEpoch();

    if (elapsedSeconds < Constants::VM_START_BUFFER_S) {
      return callback(jsonError("Scan is still initializing. Please wait."));
    }

    LOG_DEBUG << "buffer has passed, ready to retrieve scan results";

    

    return callback(jsonOk("Scan is ready for processing"));
  } catch (const std::exception &e) {
    return callback(jsonError(std::string("Internal server error: ") + e.what(),
                              drogon::HttpStatusCode::k500InternalServerError));
  }
}
