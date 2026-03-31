#pragma once

#include <fstream>
#include <mutex>
#include <string>

class FileLogger {
private:
  static std::ofstream m_logFile;
  static std::mutex m_mutex;
  static bool m_initialized;

  static std::string getTimestamp();
  static std::string buildDefaultLogPath();
  static bool ensureDirectoryExists(const std::string &path);
  static bool openWithFallback(const std::string &requestedPath,
                               std::string &openedPath);

public:
  static void init(const std::string &logPath = "");
  static void log(const std::string &message);
  static void error(const std::string &message);
  static void close();
};
