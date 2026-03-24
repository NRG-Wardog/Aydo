#include "FileLogger.hpp"

#include <windows.h>

#include <chrono>
#include <iomanip>
#include <sstream>

std::ofstream FileLogger::m_logFile;
std::mutex FileLogger::m_mutex;
bool FileLogger::m_initialized = false;

std::string FileLogger::getTimestamp() {
  const auto now = std::chrono::system_clock::now();
  const auto time = std::chrono::system_clock::to_time_t(now);
  std::tm tm{};
  localtime_s(&tm, &time);

  std::ostringstream oss;
  oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
  return oss.str();
}

std::string FileLogger::buildDefaultLogPath() {
  constexpr DWORD MAX_ENV_CHARS = 32767;
  constexpr const char *LOG_FILE_NAME = "aydo_service.log";

  std::string envBuffer(MAX_ENV_CHARS, '\0');
  char *envRaw = &envBuffer[0];

  DWORD len = GetEnvironmentVariableA("ProgramData", envRaw, MAX_ENV_CHARS);
  if (len > 0 && len < MAX_ENV_CHARS) {
    envBuffer.resize(static_cast<size_t>(len));
    return envBuffer + "\\Aydo\\logs\\" + LOG_FILE_NAME;
  }

  len = GetEnvironmentVariableA("TEMP", envRaw, MAX_ENV_CHARS);
  if (len > 0 && len < MAX_ENV_CHARS) {
    envBuffer.resize(static_cast<size_t>(len));
    return envBuffer + "\\" + LOG_FILE_NAME;
  }

  return LOG_FILE_NAME;
}

bool FileLogger::ensureDirectoryExists(const std::string &path) {
  const size_t separatorPos = path.find_last_of("\\/");
  if (separatorPos == std::string::npos) {
    return true;
  }

  const std::string dirPath = path.substr(0, separatorPos);
  if (dirPath.empty()) {
    return true;
  }

  std::string currentPath;
  currentPath.reserve(dirPath.size());

  for (size_t i = 0; i < dirPath.size(); ++i) {
    const char ch = dirPath[i];
    currentPath.push_back(ch);

    const bool isSeparator = (ch == '\\' || ch == '/');
    const bool isLastChar = (i + 1 == dirPath.size());
    if (!isSeparator && !isLastChar) {
      continue;
    }

    if (currentPath.size() <= 3 && currentPath.find(':') != std::string::npos) {
      continue;
    }

    if (!CreateDirectoryA(currentPath.c_str(), nullptr)) {
      const DWORD error = GetLastError();
      if (error != ERROR_ALREADY_EXISTS) {
        return false;
      }
    }
  }

  if (!CreateDirectoryA(dirPath.c_str(), nullptr)) {
    const DWORD error = GetLastError();
    if (error != ERROR_ALREADY_EXISTS) {
      return false;
    }
  }

  return true;
}

bool FileLogger::openWithFallback(const std::string &requestedPath,
                                  std::string &openedPath) {
  std::string candidatePath = requestedPath;
  if (candidatePath.empty()) {
    candidatePath = buildDefaultLogPath();
  }

  if (ensureDirectoryExists(candidatePath)) {
    m_logFile.open(candidatePath, std::ios::out | std::ios::app);
    if (m_logFile.is_open()) {
      openedPath = candidatePath;
      return true;
    }
  }

  const std::string fallbackPath = "aydo_service.log";
  m_logFile.open(fallbackPath, std::ios::out | std::ios::app);
  if (m_logFile.is_open()) {
    openedPath = fallbackPath;
    return true;
  }

  return false;
}

void FileLogger::init(const std::string &logPath) {
  std::lock_guard<std::mutex> lock(m_mutex);
  if (m_initialized) {
    return;
  }

  std::string openedPath;
  if (!openWithFallback(logPath, openedPath)) {
    m_initialized = false;
    return;
  }

  m_initialized = true;
  m_logFile << "\n========================================\n";
  m_logFile << "Service started: " << getTimestamp() << "\n";
  m_logFile << "Log path: " << openedPath << "\n";
  m_logFile << "========================================\n";
  m_logFile.flush();
}

void FileLogger::log(const std::string &message) {
  std::lock_guard<std::mutex> lock(m_mutex);
  if (!m_initialized || !m_logFile.is_open()) {
    return;
  }

  m_logFile << "[" << getTimestamp() << "] " << message << "\n";
  m_logFile.flush();
}

void FileLogger::error(const std::string &message) {
  std::lock_guard<std::mutex> lock(m_mutex);
  if (!m_initialized || !m_logFile.is_open()) {
    return;
  }

  m_logFile << "[" << getTimestamp() << "] ERROR: " << message << "\n";
  m_logFile.flush();
}

void FileLogger::close() {
  std::lock_guard<std::mutex> lock(m_mutex);
  if (!m_initialized || !m_logFile.is_open()) {
    return;
  }

  m_logFile << "Service stopped: " << getTimestamp() << "\n";
  m_logFile.close();
  m_initialized = false;
}
