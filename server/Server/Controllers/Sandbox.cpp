#include "Sandbox.hpp"

#include <drogon/HttpResponse.h>
#include <drogon/HttpTypes.h>
#include <drogon/MultiPart.h>
#include <filesystem>
#include <fstream>
#include <thread>

#include "../Constants.hpp"
#include "../Models/Scan.hpp"
#include "../Utils/Responses.hpp"
#include "../Utils/ScanProcessingCron.hpp"
#include "../Utils/Validation.hpp"
#include "../Utils/VmRunner.hpp"

namespace fs = std::filesystem;

void API::Sandbox::_requestFileScan(
    const drogon::HttpRequestPtr &req,
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

  if (!fileHash) {
    return callback(jsonError("Invalid or missing fileHash"));
  }

  if (!runtime) {
    return callback(jsonError("Invalid or missing runtime"));
  }

  try {
    auto dbClient = drogon::app().getDbClient();

    // Check for existing scan
    auto existingScan = Models::Scan::getByFileHash(dbClient, *fileHash);

    if (existingScan.has_value()) {
      bool shouldRetry = false;
      if (existingScan->getStatus() == Models::ScanStatus::Failed) {
        auto now = trantor::Date::now();
        auto lastUpdated = existingScan->getUpdatedAt();
        if (now.secondsSinceEpoch() - lastUpdated.secondsSinceEpoch() >= Constants::RETRY_SCAN_IF_FAILED_SECONDS) {
          shouldRetry = true;
        }
      }

      if (!shouldRetry) {
        // Return existing scan status
        Json::Value resp;
        resp["message"] = "Scan found";
        resp["status"] = Models::Scan::statusToString(existingScan->getStatus());
        resp["virusType"] =
            Models::Scan::virusTypeToString(existingScan->getVirusType());
        resp["runtime"] = existingScan->getRuntime();
        resp["score"] = existingScan->getScore();

        return callback(jsonOk(resp));
      }

      // If shouldRetry is true, we update the existing scan to Pending
      Models::Scan::resetScan(dbClient, *fileHash, std::stoi(*runtime));
      Json::Value resp;
      resp["message"] = "Scan retrying";
      resp["status"] = Models::Scan::statusToString(Models::ScanStatus::Pending);
      resp["virusType"] =
          Models::Scan::virusTypeToString(Models::VirusType::Clean);
      resp["runtime"] = std::stoi(*runtime);
      resp["score"] = 0;

      return callback(jsonOk(resp, drogon::HttpStatusCode::k201Created));
    }

    // Create new scan
    Models::Scan newScan;
    newScan.setFileHash(*fileHash);
    newScan.setStatus(Models::ScanStatus::Pending);
    newScan.setVirusType(Models::VirusType::Clean);
    newScan.setRuntime(std::stoi(*runtime));
    newScan.setScore(0);

    Models::Scan::create(dbClient, newScan);

    Json::Value resp;
    resp["message"] = "Scan created";
    resp["status"] = Models::Scan::statusToString(newScan.getStatus());
    resp["virusType"] = Models::Scan::virusTypeToString(newScan.getVirusType());
    resp["runtime"] = newScan.getRuntime();
    resp["score"] = newScan.getScore();

    return callback(jsonOk(resp, drogon::HttpStatusCode::k201Created));
  } catch (const std::exception &e) {
    return callback(jsonError(std::string("Internal server error: ") + e.what(),
                              drogon::HttpStatusCode::k500InternalServerError));
  }
}

void API::Sandbox::_uploadFile(
    const drogon::HttpRequestPtr &req,
    std::function<void(const drogon::HttpResponsePtr &)> &&callback) {
  LOG_DEBUG << "Got an upload file request";

  // Parse multipart form data
  drogon::MultiPartParser fileUpload;

  if (fileUpload.parse(req) != 0) {
    return callback(jsonError("Failed to parse multipart form data"));
  }

  // Get fileHash from form parameters
  const auto &params = fileUpload.getParameters();
  auto fileHashIt = params.find("fileHash");

  if (fileHashIt == params.end() || fileHashIt->second.empty()) {
    return callback(jsonError("Missing fileHash parameter"));
  }

  const std::string &fileHash = fileHashIt->second;

  // Validate fileHash format
  if (!Utils::Validation::isValidFileHash(fileHash)) {
    return callback(jsonError("Invalid fileHash format"));
  }

  // Ensure exactly one file is provided
  const auto &files = fileUpload.getFiles();

  if (files.size() != 1) {
    return callback(jsonError("Exactly one file must be provided"));
  }

  try {
    auto dbClient = drogon::app().getDbClient();

    // Check if scan exists
    auto existingScan = Models::Scan::getByFileHash(dbClient, fileHash);

    if (!existingScan.has_value()) {
      return callback(jsonError("Scan not found. Request a scan first.",
                                drogon::HttpStatusCode::k404NotFound));
    }

    // Create uploads directory if it doesn't exist
    fs::path uploadsDir = Constants::UPLOADS_DIRECTORY;
    if (!fs::exists(uploadsDir)) {
      fs::create_directories(uploadsDir);
    }

    // Save file with fileHash as filename
    const auto &uploadedFile = files[0];
    fs::path filePath = uploadsDir / fileHash;

    // Write file to disk
    std::ofstream outFile(filePath, std::ios::binary);
    if (!outFile) {
      return callback(jsonError("Failed to save file",
                                drogon::HttpStatusCode::k500InternalServerError));
    }

    outFile.write(uploadedFile.fileData(),
                  static_cast<std::streamsize>(uploadedFile.fileLength()));
    outFile.close();

    // Update scan status to InProgress
    Models::Scan::updateStatus(dbClient, fileHash, Models::ScanStatus::InProgress);

    // Launch VMRunner in a separate thread (blocking operation)
    const int runtime = existingScan->getRuntime();
    const std::string sandboxId = fileHash;
    std::thread vmThread([dbClient, fileHash, sandboxId, runtime, filePath]() {
      const bool success =
          Utils::VmRunner::startVm(sandboxId, filePath, runtime);
      if (!success) {
        LOG_WARN << "VMRunner execution failed (sandboxId=" << sandboxId
                 << ")";
        Models::Scan::updateResult(dbClient, fileHash,
                                   Models::ScanStatus::Failed,
                                   Models::VirusType::Unknown, 0);
        return;
      }

      Models::Scan scanForProcessing;
      scanForProcessing.setFileHash(fileHash);
      const auto outcome =
          Utils::ScanProcessingCron::runDynamicScan(scanForProcessing);
      Models::Scan::updateResult(dbClient, fileHash, outcome.status,
                                 outcome.virusType, outcome.score);
    });
    vmThread.detach();

    Json::Value resp;
    resp["message"] = "File uploaded successfully";
    resp["fileHash"] = fileHash;
    resp["status"] = Models::Scan::statusToString(Models::ScanStatus::InProgress);

    return callback(jsonOk(resp));
  } catch (const std::exception &e) {
    return callback(jsonError(std::string("Internal server error: ") + e.what(),
                              drogon::HttpStatusCode::k500InternalServerError));
  }
}
