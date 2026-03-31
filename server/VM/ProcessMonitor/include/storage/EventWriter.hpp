#pragma once
#include "pch.h"
#include <krabs.hpp>

#include <atomic>
#include <fstream>
#include <mutex>
#include <sqlite3.h>
#include "Finding.hpp"

struct Finding;

class EventWriter {
public:
  enum class WireFormat { JsonLines,
                          Msgpack,
                          Sqlite };

  explicit EventWriter(std::wstring path,
                       WireFormat fmt = WireFormat::Sqlite,
                       bool pretty = false,
                       bool lengthPrefixed = true);
  ~EventWriter() noexcept;

  void flush();
  void operator()(const EVENT_RECORD &rec, const krabs::trace_context &ctx);
  void writeEventJson(nlohmann::json eventJson);

  void setFormat(WireFormat f, bool lengthPrefixed = true) {
    std::scoped_lock<std::mutex> lk(m_mtx);
    m_wireFormat = f;
    m_lengthPrefixed = lengthPrefixed;
    _ensureSinkOpenLocked();
  }
  void writeFinding(const Finding &f);

private:
  void _writeAuxEventTables(const nlohmann::json &j);
  void _flattenJsonOneLevel(const nlohmann::json &obj,
                            const std::string &prefix,
                            std::vector<std::pair<std::string, nlohmann::json>> &out);
  void _writeEventJson(const EVENT_RECORD &rec, const krabs::trace_context &ctx);
  void _collectColumnsAndValues(const nlohmann::json &j,
                                std::vector<std::string> &columns,
                                std::vector<nlohmann::json> &values) const;
  void _writeToSqlite(const nlohmann::json &j);
  void _initSqliteSchema();
  void _ensureEventsColumns();
  void _writeOut(const nlohmann::json &j);

  void _fillPropsViaTdh(nlohmann::json &props,
                        const EVENT_RECORD &rec,
                        const krabs::trace_context &ctx) const;
  std::string _buildInsertSql(const std::vector<std::string> &columns) const;

  bool _prepareInsertStatement(const std::string &sql, sqlite3_stmt **stmtOut);

  bool _bindJsonValues(sqlite3_stmt *stmt,
                       const std::vector<nlohmann::json> &values) const;
  void _enrichSigmaFields(nlohmann::json &j) const;
  void _ensureSinkOpenLocked();

private:
  static constexpr std::uint64_t INITIAL_FALLBACK_EVENT_RECORD_ID = 1;

  std::mutex m_mtx;
  std::ofstream m_out;
  std::wstring m_path;
  bool m_pretty = false;

  WireFormat m_wireFormat = WireFormat::Sqlite;
  sqlite3 *m_db = nullptr;

  bool m_lengthPrefixed = true;
  std::atomic_uint64_t m_fallbackEventRecordId{INITIAL_FALLBACK_EVENT_RECORD_ID};
};

