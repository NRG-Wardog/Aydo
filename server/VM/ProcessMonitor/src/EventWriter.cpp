#include "EventWriter.hpp"

#include <tdh.h>
#include <array>
#include <format>
#include <iomanip>
#include <objbase.h>
#include <sstream>
#include <stdexcept>
#include <unordered_set>

#include "Constants.hpp"
#include "EventWriterConstants.hpp"
#include "SafeKrabsParser.hpp"
#include "SqlRequests.hpp"
#include "Utils.hpp"
#include "AttackMetadata.hpp"

namespace EventWriterMigrationConstants {
inline constexpr std::array<const char *, 8> s_coreSysmonColumns = {
    "ProcessGuid",
    "ParentProcessGuid",
    "RuleName",
    "UtcTime",
    "CurrentDirectory",
    "LogonGuid",
    "LogonId",
    "TerminalSessionId",
};

inline constexpr const char *s_eventsTableInfoSql = "PRAGMA table_info(Events);";
} // namespace EventWriterMigrationConstants

static void s_execSql(sqlite3 *db, const char *sql, const char *tag) {
  if (!db || !sql) {
    return;
  }

  char *errMsg = nullptr;
  const int rc = sqlite3_exec(db, sql, nullptr, nullptr, &errMsg);
  if (rc != SQLITE_OK) {
    std::string msg = std::format("{} failed, rc={}", tag ? tag : "sqlite3_exec", rc);
    if (errMsg) {
      msg += ", err=";
      msg += errMsg;
      sqlite3_free(errMsg);
    }
    msg += "\n";
    OutputDebugStringA(msg.c_str());
  }
}

static void s_ensureFindingsSchema(sqlite3 *db) {
  s_execSql(db, EventWriterConstants::FINDINGS_DDL, "sqlite3_exec(FINDINGS_DDL)");
}

static bool s_tableHasColumn(sqlite3 *db, const char *tableName, const char *columnName) {
  if (!db || !tableName || !columnName) {
    return false;
  }

  std::string pragma = "PRAGMA table_info(";
  pragma += tableName;
  pragma += ");";

  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(db, pragma.c_str(), -1, &stmt, nullptr) != SQLITE_OK || !stmt) {
    if (stmt) {
      sqlite3_finalize(stmt);
    }
    return false;
  }

  bool found = false;
  while (sqlite3_step(stmt) == SQLITE_ROW) {
    const auto *name = reinterpret_cast<const char *>(sqlite3_column_text(stmt, EventWriterConstants::PRAGMA_TABLE_INFO_NAME_COLUMN_INDEX));
    if (!name) {
      continue;
    }
    if (Utils::toLower(std::string(name)) == Utils::toLower(std::string(columnName))) {
      found = true;
      break;
    }
  }

  sqlite3_finalize(stmt);
  return found;
}

static void s_ensureTableColumn(sqlite3 *db,
                                const char *tableName,
                                const char *columnName,
                                const char *columnDefinition) {
  if (!db || !tableName || !columnName || !columnDefinition) {
    return;
  }

  if (s_tableHasColumn(db, tableName, columnName)) {
    return;
  }

  std::string sql = "ALTER TABLE ";
  sql += tableName;
  sql += " ADD COLUMN ";
  sql += columnDefinition;
  sql += ";";
  s_execSql(db, sql.c_str(), "sqlite3_exec(ALTER_TABLE_ADD_COLUMN)");
}

static void s_ensureAttackColumns(sqlite3 *db) {
  if (!db) {
    return;
  }

  s_ensureTableColumn(db, "Events", "AttackTactic", "AttackTactic TEXT");
  s_ensureTableColumn(db, "Events", "AttackTechnique", "AttackTechnique TEXT");
  s_ensureTableColumn(db, "Events", "AttackSubTechnique", "AttackSubTechnique TEXT");
  s_ensureTableColumn(db, "Events", "AttackReference", "AttackReference TEXT");
  s_ensureTableColumn(db, "Events", "Prevention", "Prevention TEXT");

  s_ensureTableColumn(db, "Findings", "AttackTactic", "AttackTactic TEXT");
  s_ensureTableColumn(db, "Findings", "AttackTechnique", "AttackTechnique TEXT");
  s_ensureTableColumn(db, "Findings", "AttackSubTechnique", "AttackSubTechnique TEXT");
  s_ensureTableColumn(db, "Findings", "AttackReference", "AttackReference TEXT");
  s_ensureTableColumn(db, "Findings", "Prevention", "Prevention TEXT");
}

EventWriter::EventWriter(std::wstring path,
                         WireFormat fmt,
                         bool pretty,
                         bool length_prefixed)
    : m_path(std::move(path))
    , m_pretty(pretty)
    , m_wireFormat(fmt)
    , m_db(nullptr)
    , m_lengthPrefixed(length_prefixed) {

  std::scoped_lock<std::mutex> lk(m_mtx);
  _ensureSinkOpenLocked();
}

EventWriter::~EventWriter() {
  try {
    std::scoped_lock<std::mutex> lk(m_mtx);

    if (m_db) {
      sqlite3_close_v2(m_db);
      m_db = nullptr;
    }

    if (m_out.is_open()) {
      m_out.flush();
      m_out.close();
    }
  } catch (...) {
  }
}

void EventWriter::_writeToSqlite(const nlohmann::json &j) {
  if (!m_db || !j.is_object()) {
    OutputDebugStringA("_writeToSqlite: no DB handle or JSON is not an object\n");
    return;
  }

  std::vector<std::string> columns;
  std::vector<nlohmann::json> values;

  _collectColumnsAndValues(j, columns, values);

  if (columns.empty()) {
    OutputDebugStringA("_writeToSqlite: no columns collected for INSERT\n");
    return;
  }

  const std::string sql = _buildInsertSql(columns);

  sqlite3_stmt *stmt = nullptr;
  if (!_prepareInsertStatement(sql, &stmt)) {
    OutputDebugStringA("_writeToSqlite: _prepareInsertStatement failed\n");
    return;
  }

  if (!_bindJsonValues(stmt, values)) {
    OutputDebugStringA("_writeToSqlite: _bindJsonValues failed\n");
    sqlite3_finalize(stmt);
    return;
  }

  if (const int rc = sqlite3_step(stmt); rc != SQLITE_DONE) {

    std::string msg = std::format("_writeToSqlite: sqlite3_step failed, rc={}",
                                  std::to_string(rc));
    if (m_db) {
      msg += ", err=";
      msg += sqlite3_errmsg(m_db);
    }
    msg += "\n";
    OutputDebugStringA(msg.c_str());
  } else {
    OutputDebugStringA("_writeToSqlite: inserted one event\n");

    _writeAuxEventTables(j);
  }

  sqlite3_finalize(stmt);
}

void EventWriter::_initSqliteSchema() {
  if (!m_db) {
    return;
  }

  s_execSql(m_db, SqlRequests::TABLES_CREATE, "sqlite3_exec(TABLES_CREATE)");
  _ensureEventsColumns();
  // Always attempt Findings DDL independently in case legacy Events schema migration fails.
  s_ensureFindingsSchema(m_db);
  s_ensureAttackColumns(m_db);
}

void EventWriter::_ensureEventsColumns() {
  if (!m_db) {
    return;
  }

  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(m_db,
                         EventWriterMigrationConstants::s_eventsTableInfoSql,
                         EventWriterConstants::SQLITE_AUTO_LENGTH,
                         &stmt,
                         nullptr) != SQLITE_OK ||
      !stmt) {
    if (stmt) {
      sqlite3_finalize(stmt);
    }

    OutputDebugStringA("_ensureEventsColumns: PRAGMA table_info(Events) prepare failed\n");
    return;
  }

  std::unordered_set<std::string> existingColumns;
  while (sqlite3_step(stmt) == SQLITE_ROW) {
    const auto *name = sqlite3_column_text(stmt, EventWriterConstants::PRAGMA_TABLE_INFO_NAME_COLUMN_INDEX);
    if (name) {
      existingColumns.emplace(reinterpret_cast<const char *>(name));
    }
  }
  sqlite3_finalize(stmt);

  for (const auto *columnName : EventWriterMigrationConstants::s_coreSysmonColumns) {
    if (existingColumns.contains(columnName)) {
      continue;
    }

    const std::string alterSql = std::format("ALTER TABLE Events ADD COLUMN \"{}\" TEXT;", columnName);
    char *errMsg = nullptr;
    const int rc = sqlite3_exec(m_db, alterSql.c_str(), nullptr, nullptr, &errMsg);
    if (rc != SQLITE_OK) {
      std::string msg = std::format("_ensureEventsColumns: failed adding '{}' rc={}", columnName, rc);
      if (errMsg) {
        msg += ", err=";
        msg += errMsg;
        sqlite3_free(errMsg);
      }
      msg += "\n";
      OutputDebugStringA(msg.c_str());
    }
  }
}

bool EventWriter::_bindJsonValues(sqlite3_stmt *stmt,
                                  const std::vector<nlohmann::json> &values) const {
  if (!stmt) {
    return false;
  }

  for (size_t i = 0; i < values.size(); ++i) {
    const auto &val = values[i];
    const auto idx = static_cast<int>(i + EventWriterConstants::SQLITE_INDEX_BASE);

    int rc = SQLITE_OK;

    if (val.is_number_integer()) {
      rc = sqlite3_bind_int64(stmt, idx, val.get<long long>());
    } else if (val.is_number_unsigned()) {
      rc = sqlite3_bind_int64(
          stmt, idx,
          static_cast<sqlite3_int64>(val.get<unsigned long long>()));
    } else if (val.is_number_float()) {
      rc = sqlite3_bind_double(stmt, idx, val.get<double>());
    } else if (val.is_boolean()) {
      rc = sqlite3_bind_int(stmt, idx, val.get<bool>() ? 1 : 0);
    } else if (val.is_string()) {
      const std::string &s = val.get_ref<const std::string &>();
      rc = sqlite3_bind_text(stmt, idx, s.c_str(), EventWriterConstants::SQLITE_AUTO_LENGTH, SQLITE_TRANSIENT);
    } else {
      // Fallback: store as JSON text.
      const std::string s = val.dump();
      rc = sqlite3_bind_text(stmt, idx, s.c_str(), EventWriterConstants::SQLITE_AUTO_LENGTH, SQLITE_TRANSIENT);
    }

    if (rc != SQLITE_OK) {
      return false;
    }
  }

  return true;
}

bool EventWriter::_prepareInsertStatement(const std::string &sql, sqlite3_stmt **stmtOut) {
  if (!m_db || !stmtOut) {
    return false;
  }

  *stmtOut = nullptr;

  if (const int rc = sqlite3_prepare_v2(m_db, sql.c_str(), EventWriterConstants::SQLITE_AUTO_LENGTH, stmtOut, nullptr); rc != SQLITE_OK || !*stmtOut) {
    if (*stmtOut) {
      sqlite3_finalize(*stmtOut);
      *stmtOut = nullptr;
    }
    // Optional: log the error with sqlite3_errmsg(m_db).
    return false;
  }

  return true;
}

std::string EventWriter::_buildInsertSql(const std::vector<std::string> &columns) const {
  std::ostringstream sql;

  sql << "INSERT INTO Events(";
  for (size_t i = 0; i < columns.size(); ++i) {
    if (i > 0) {
      sql << ",";
    }
    // Quote identifiers in case some are reserved words (e.g. State).
    sql << "\"" << columns[i] << "\"";
  }

  sql << ") VALUES(";
  for (size_t i = 0; i < columns.size(); ++i) {
    if (i > 0) {
      sql << ",";
    }
    sql << "?";
  }
  sql << ");";

  return sql.str();
}

void EventWriter::_collectColumnsAndValues(const nlohmann::json &j,
                                           std::vector<std::string> &columns,
                                           std::vector<nlohmann::json> &values) const {
  columns.clear();
  values.clear();

  //
  // Read the actual table schema (once per DB handle) so we are not limited to
  // SqlRequests::TABLES. This allows new columns to be written without touching code.
  //
  auto getEventsTableColumns = [&]() -> const std::vector<std::string> & {
    static std::mutex s_colsMtx;
    static sqlite3 *s_lastDb = nullptr;
    static std::vector<std::string> s_cols;

    std::scoped_lock<std::mutex> lk(s_colsMtx);

    if (!m_db) {
      return s_cols; // likely empty
    }

    if (s_lastDb == m_db && !s_cols.empty()) {
      return s_cols;
    }

    s_lastDb = m_db;
    s_cols.clear();

    sqlite3_stmt *stmt = nullptr;
    const char *sql = "PRAGMA table_info(Events);";
    if (sqlite3_prepare_v2(m_db, sql, EventWriterConstants::SQLITE_AUTO_LENGTH, &stmt, nullptr) != SQLITE_OK || !stmt) {
      if (stmt) {
        sqlite3_finalize(stmt);
      }
      return s_cols;
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
      // PRAGMA table_info columns: (cid, name, type, notnull, dflt_value, pk)
      const unsigned char *txt = sqlite3_column_text(stmt, EventWriterConstants::PRAGMA_TABLE_INFO_NAME_COLUMN_INDEX);
      if (!txt) {
        continue;
      }
      std::string colName = reinterpret_cast<const char *>(txt);

      // Keep DEFAULT CURRENT_TIMESTAMP behavior.
      if (colName == "InsertionTime") {
        continue;
      }

      s_cols.push_back(std::move(colName));
    }

    sqlite3_finalize(stmt);
    return s_cols;
  };

  const auto &schemaCols = getEventsTableColumns();
  const auto &colsToWalk = schemaCols; // fallback

  auto findInObjects = [&](const std::string &key) -> const nlohmann::json * {
    if (auto it = j.find(key); it != j.end() && !it->is_null()) {
      return &it.value();
    }

    for (const auto *cat : EventWriterConstants::EVENT_BUCKET_NAMES) {
      if (auto catIt = j.find(cat); catIt != j.end() && catIt->is_object()) {
        if (auto it = catIt->find(key); it != catIt->end() && !it->is_null()) {
          return &it.value();
        }
      }
    }
    return nullptr;
  };

  // Helpful for bridging PascalCase columns (UserSid) to snake_case payload keys (user_sid)
  auto findSnakeCase = [&](const std::string &key) -> const nlohmann::json * {
    std::string snake;
    snake.reserve(key.size() + Constants::SNAKE_CASE_EXTRA_CAPACITY);

    for (size_t i = 0; i < key.size(); ++i) {
      const auto c = static_cast<unsigned char>(key[i]);
      if (c >= 'A' && c <= 'Z') {
        if (i != 0) {
          snake.push_back('_');
        }
        snake.push_back(static_cast<char>(c - 'A' + 'a'));
      } else {
        snake.push_back(static_cast<char>(c));
      }
    }
    if (snake == key) {
      return nullptr;
    }
    return findInObjects(snake);
  };

  for (const auto &colName : colsToWalk) {
    const nlohmann::json *src = nullptr;

    //
    // Explicit mappings for "header" fields where the JSON key differs
    // from the SQL column name.
    //
    if (colName == "EventId") {
      if (j.contains("event_id")) {
        src = &j["event_id"];
      } else if (j.contains("EventId")) {
        src = &j["EventId"];
      }
    } else if (colName == "EventRecordId") {
      if (j.contains("EventRecordId")) {
        src = &j["EventRecordId"];
      } else if (j.contains("event_record_id")) {
        src = &j["event_record_id"];
      }
    } else if (colName == "EventTime") {
      if (j.contains("ts")) {
        src = &j["ts"];
      } else if (j.contains("EventTime")) {
        src = &j["EventTime"];
      }
    } else if (colName == "Computer") {
      if (j.contains("host")) {
        src = &j["host"];
      } else if (j.contains("Computer")) {
        src = &j["Computer"];
      }
    } else if (colName == "Provider" && j.contains("provider")) {
      src = &j["provider"];
    } else if (colName == "Category" && j.contains("category")) {
      src = &j["category"];
    } else if (colName == "pid" && j.contains("pid")) {
      src = &j["pid"];
    } else if (colName == "tid" && j.contains("tid")) {
      src = &j["tid"];
    } else {
      // generic: same name in top-level OR nested (props/proc/net/dns/file)
      src = findInObjects(colName);
      if (!src) {
        src = findSnakeCase(colName);
      }
    }

    if (src && !src->is_null()) {
      columns.push_back(colName);
      values.push_back(*src);
    }
  }
}

void EventWriter::flush() {
  std::scoped_lock<std::mutex> lk(m_mtx);

  if (m_wireFormat != WireFormat::Sqlite && m_out.is_open()) {
    m_out.flush();
  }
}

void EventWriter::_fillPropsViaTdh(nlohmann::json &props,
                                   const EVENT_RECORD &rec,
                                   const krabs::trace_context &ctx) const {
  try {
    // 1. Get Event Information
    ULONG size = 0;
    ::TdhGetEventInformation(const_cast<EVENT_RECORD *>(&rec), 0, nullptr, nullptr, &size);
    if (size == 0) {
      return;
    }

    std::vector<BYTE> buf(size);
    auto *info = reinterpret_cast<TRACE_EVENT_INFO *>(buf.data());
    if (TdhGetEventInformation(const_cast<EVENT_RECORD *>(&rec), 0, nullptr, info, &size) != ERROR_SUCCESS) {
      return;
    }

    krabs::schema schema(rec, ctx.schema_locator);
    SafeKrabsParserSession parser(schema);
    bool loggedFatalParserState = false;
    auto logFatalParserState = [&]() {
      if (loggedFatalParserState || !parser.isPoisoned()) {
        return;
      }

      std::string provider = "<unknown_provider>";
      try {
        provider = Utils::narrow_utf8(schema.provider_name());
      } catch (...) {
      }

      const int eventId = static_cast<int>(rec.EventHeader.EventDescriptor.Id);
      const std::string msg = std::format(
          "krabs parser fatal state: provider='{}' event_id={} payload/schema mismatch; remaining properties marked <parse_error>\n",
          provider,
          eventId);
      OutputDebugStringA(msg.c_str());
      loggedFatalParserState = true;
    };

    for (ULONG i = 0; i < info->TopLevelPropertyCount; ++i) {
      auto const &epi = info->EventPropertyInfoArray[i];
      const auto *wname = reinterpret_cast<const wchar_t *>(buf.data() + epi.NameOffset);
      const std::string name = Utils::narrow_utf8(wname);

      if (SqlRequests::SKIP_FIELDS.contains(name)) {
        props[name] = "<skipped>";
        continue;
      }

      if (parser.isPoisoned()) {
        props[name] = "<parse_error>";
        logFatalParserState();
        continue;
      }

      const bool wasPoisoned = parser.isPoisoned();
      bool parsed = false;

      switch (epi.nonStructType.InType) {
      // Strings
      case TDH_INTYPE_UNICODESTRING:
        if (auto v = parser.tryParse<std::wstring>(wname)) {
          props[name] = Utils::narrow_utf8(*v);
          parsed = true;
        }
        break;
      case TDH_INTYPE_ANSISTRING:
        if (auto v = parser.tryParse<std::string>(wname)) {
          props[name] = *v;
          parsed = true;
        }
        break;
      case TDH_INTYPE_INT8:
        if (auto v = parser.tryParse<int8_t>(wname)) {
          props[name] = *v;
          parsed = true;
        }
        break;
      case TDH_INTYPE_UINT8:
        if (auto v = parser.tryParse<uint8_t>(wname)) {
          props[name] = *v;
          parsed = true;
        }
        break;
      case TDH_INTYPE_INT16:
        if (auto v = parser.tryParse<int16_t>(wname)) {
          props[name] = *v;
          parsed = true;
        }
        break;
      case TDH_INTYPE_UINT16:
        if (auto v = parser.tryParse<uint16_t>(wname)) {
          props[name] = *v;
          parsed = true;
        }
        break;
      case TDH_INTYPE_INT32:
        if (auto v = parser.tryParse<int32_t>(wname)) {
          props[name] = *v;
          parsed = true;
        }
        break;
      case TDH_INTYPE_UINT32:
        if (auto v = parser.tryParse<uint32_t>(wname)) {
          props[name] = *v;
          parsed = true;
        }
        break;
      case TDH_INTYPE_INT64:
        if (auto v = parser.tryParse<int64_t>(wname)) {
          props[name] = *v;
          parsed = true;
        }
        break;
      case TDH_INTYPE_UINT64:
        if (auto v = parser.tryParse<uint64_t>(wname)) {
          props[name] = *v;
          parsed = true;
        }
        break;
      case TDH_INTYPE_BOOLEAN:
        if (auto v = parser.tryParse<bool>(wname)) {
          props[name] = *v;
          parsed = true;
        }
        break;

      // Hex / Pointers
      case TDH_INTYPE_POINTER:
      case TDH_INTYPE_HEXINT32:
      case TDH_INTYPE_HEXINT64: {
        std::optional<uint64_t> parsedHex;
        if (epi.length == EventWriterConstants::UINT32_BYTE_WIDTH) {
          if (auto v = parser.tryParse<uint32_t>(wname)) {
            parsedHex = static_cast<uint64_t>(*v);
          }
        } else {
          parsedHex = parser.tryParse<uint64_t>(wname);
        }
        if (parsedHex) {
          props[name] = (std::ostringstream() << "0x" << std::hex << std::nouppercase << *parsedHex).str();
          parsed = true;
        }
        break;
      }

      // GUIDs
      case TDH_INTYPE_GUID: {
        if (auto g = parser.tryParse<GUID>(wname)) {
          wchar_t bufGuid[Constants::GUID_STRING_BUFFER_CHARS];
          props[name] = StringFromGUID2(*g, bufGuid, Constants::GUID_STRING_BUFFER_CHARS) ? Utils::narrow_utf8(bufGuid) : "<unsupported>";
          parsed = true;
        }
        break;
      }

      default: // Fallback
        if (auto v = parser.tryParse<std::wstring>(wname)) {
          props[name] = Utils::narrow_utf8(*v);
          parsed = true;
        }
        break;
      }

      if (!parsed) {
        props[name] = "<parse_error>";
      }

      if (!wasPoisoned && parser.isPoisoned()) {
        logFatalParserState();
      }
    }
  } catch (const std::exception &e) {
    OutputDebugStringA((std::string("krabs error: ") + e.what() + "\n").c_str());
  }
}

void EventWriter::_flattenJsonOneLevel(const nlohmann::json &obj,
                                       const std::string &prefix,
                                       std::vector<std::pair<std::string, nlohmann::json>> &out) {
  if (!obj.is_object()) {
    return;
  }

  for (auto it = obj.begin(); it != obj.end(); ++it) {
    const std::string k = prefix.empty() ? it.key() : (prefix + "." + it.key());
    const nlohmann::json &v = it.value();
    if (v.is_null()) {
      continue;
    }

    out.emplace_back(k, v);
  }
}

void EventWriter::_writeAuxEventTables(const nlohmann::json &j) {
  if (!m_db || !j.is_object()) {
    return;
  }

  auto itId = j.find("EventRecordId");
  if (itId == j.end() || !itId->is_number()) {
    return;
  }
  const long long eventRecordId = itId->get<long long>();

  {
    const char *sql =
        "INSERT OR REPLACE INTO EventPayloads (EventRecordId, JsonText) VALUES (?, ?);";

    sqlite3_stmt *stmt = nullptr;
    if (sqlite3_prepare_v2(m_db, sql, EventWriterConstants::SQLITE_AUTO_LENGTH, &stmt, nullptr) == SQLITE_OK && stmt) {
      sqlite3_bind_int64(stmt, EventWriterConstants::PAYLOAD_BIND_EVENT_RECORD_ID, eventRecordId);
      const std::string payload = j.dump(); // compact JSON
      sqlite3_bind_text(stmt, EventWriterConstants::PAYLOAD_BIND_JSON_TEXT, payload.c_str(), static_cast<int>(payload.size()), SQLITE_TRANSIENT);

      (void)sqlite3_step(stmt);
    }
    if (stmt) {
      sqlite3_finalize(stmt);
    }
  }

  {
    const char *sql =
        "INSERT OR REPLACE INTO EventFields (EventRecordId, Key, Value, ValueType) VALUES (?, ?, ?, ?);";

    sqlite3_stmt *stmt = nullptr;
    if (sqlite3_prepare_v2(m_db, sql, EventWriterConstants::SQLITE_AUTO_LENGTH, &stmt, nullptr) != SQLITE_OK || !stmt) {
      if (stmt) {
        sqlite3_finalize(stmt);
      }
      return;
    }

    std::vector<std::pair<std::string, nlohmann::json>> flat;
    flat.reserve(EventWriterConstants::FLATTENED_FIELD_RESERVE_SIZE);

    // top-level keys
    _flattenJsonOneLevel(j, "", flat);

    // common nested buckets
    for (const char *b : EventWriterConstants::EVENT_BUCKET_NAMES) {
      auto it = j.find(b);
      if (it != j.end() && it->is_object()) {
        _flattenJsonOneLevel(*it, b, flat);
      }
    }

    for (const auto &[k, v] : flat) {
      // skip very large blobs if you want; keep for now
      const std::string type = v.type_name();

      std::string valueText;
      if (v.is_string()) {
        valueText = v.get<std::string>();
      } else if (v.is_boolean()) {
        valueText = v.get<bool>() ? "true" : "false";
      } else if (v.is_number_integer()) {
        valueText = std::to_string(v.get<long long>());
      } else if (v.is_number_unsigned()) {
        valueText = std::to_string(v.get<unsigned long long>());
      } else if (v.is_number_float()) {
        valueText = std::to_string(v.get<double>());
      } else {
        valueText = v.dump(); // arrays / objects
      }

      sqlite3_reset(stmt);
      sqlite3_clear_bindings(stmt);

      sqlite3_bind_int64(stmt, EventWriterConstants::FIELD_BIND_EVENT_RECORD_ID, eventRecordId);
      sqlite3_bind_text(stmt, EventWriterConstants::FIELD_BIND_KEY, k.c_str(), static_cast<int>(k.size()), SQLITE_TRANSIENT);
      sqlite3_bind_text(stmt, EventWriterConstants::FIELD_BIND_VALUE, valueText.c_str(), static_cast<int>(valueText.size()), SQLITE_TRANSIENT);
      sqlite3_bind_text(stmt, EventWriterConstants::FIELD_BIND_VALUE_TYPE, type.c_str(), static_cast<int>(type.size()), SQLITE_TRANSIENT);

      (void)sqlite3_step(stmt);
    }

    sqlite3_finalize(stmt);
  }
}

void EventWriter::writeFinding(const Finding &f) {
  Finding finding = f;
  AttackMetadataCatalog::applyToFinding(finding);
  try {
    auto evidence = nlohmann::json::parse(finding.evidence_json);
    if (evidence.is_object()) {
      evidence["attack_tactic"] = finding.attack_tactic;
      evidence["attack_technique"] = finding.attack_technique;
      evidence["attack_sub_technique"] = finding.attack_sub_technique;
      evidence["attack_reference"] = finding.attack_reference;
      evidence["prevention"] = finding.prevention;
      finding.evidence_json = evidence.dump();
    }
  } catch (...) {
  }

  if (m_wireFormat != WireFormat::Sqlite) {
    nlohmann::json j;
    j["RecordType"] = "Finding";
    j["EventTime"] = Utils::iso8601FromTimePoint(finding.ts);
    j["Type"] = finding.type;
    j["Severity"] = finding.severity;
    j["Confidence"] = finding.confidence;
    j["SourcePid"] = finding.source_pid;
    j["TargetPid"] = finding.target_pid;
    j["Tid"] = finding.tid;
    j["EvidenceJson"] = finding.evidence_json;
    j["AttackTactic"] = finding.attack_tactic;
    j["AttackTechnique"] = finding.attack_technique;
    j["AttackSubTechnique"] = finding.attack_sub_technique;
    j["AttackReference"] = finding.attack_reference;
    j["Prevention"] = finding.prevention;
    _writeOut(j);
    return;
  }

  // insert into Findings table
  std::scoped_lock<std::mutex> lk(m_mtx);
  _ensureSinkOpenLocked();

  if (!m_db) {
    if (sqlite3_open16(m_path.c_str(), &m_db) != SQLITE_OK) {
      sqlite3_close(m_db);
      m_db = nullptr;
      return;
    }
    _initSqliteSchema();
  }

  static const char *INSERT_FINDING_SQL =
      "INSERT INTO Findings(EventTime, Type, Severity, Confidence, SourcePid, TargetPid, Tid, EvidenceJson, AttackTactic, AttackTechnique, AttackSubTechnique, AttackReference, Prevention) "
      "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?);";

  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(m_db, INSERT_FINDING_SQL, EventWriterConstants::SQLITE_AUTO_LENGTH, &stmt, nullptr) != SQLITE_OK || !stmt) {
    if (stmt) {
      sqlite3_finalize(stmt);
      stmt = nullptr;
    }

    s_ensureFindingsSchema(m_db);
    s_ensureAttackColumns(m_db);
    if (sqlite3_prepare_v2(m_db, INSERT_FINDING_SQL, EventWriterConstants::SQLITE_AUTO_LENGTH, &stmt, nullptr) != SQLITE_OK || !stmt) {
      if (stmt) {
        sqlite3_finalize(stmt);
      }
      return;
    }
  }

  const auto ts = Utils::iso8601FromTimePoint(finding.ts);

  sqlite3_bind_text(stmt, EventWriterConstants::FINDING_BIND_EVENT_TIME, ts.c_str(), EventWriterConstants::SQLITE_AUTO_LENGTH, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, EventWriterConstants::FINDING_BIND_TYPE, finding.type.c_str(), EventWriterConstants::SQLITE_AUTO_LENGTH, SQLITE_TRANSIENT);
  sqlite3_bind_int(stmt, EventWriterConstants::FINDING_BIND_SEVERITY, finding.severity);
  sqlite3_bind_int(stmt, EventWriterConstants::FINDING_BIND_CONFIDENCE, finding.confidence);
  sqlite3_bind_int(stmt, EventWriterConstants::FINDING_BIND_SOURCE_PID, static_cast<int>(finding.source_pid));
  sqlite3_bind_int(stmt, EventWriterConstants::FINDING_BIND_TARGET_PID, static_cast<int>(finding.target_pid));
  sqlite3_bind_int(stmt, EventWriterConstants::FINDING_BIND_TID, static_cast<int>(finding.tid));
  sqlite3_bind_text(stmt, EventWriterConstants::FINDING_BIND_EVIDENCE_JSON, finding.evidence_json.c_str(), EventWriterConstants::SQLITE_AUTO_LENGTH, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, EventWriterConstants::FINDING_BIND_ATTACK_TACTIC, finding.attack_tactic.c_str(), EventWriterConstants::SQLITE_AUTO_LENGTH, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, EventWriterConstants::FINDING_BIND_ATTACK_TECHNIQUE, finding.attack_technique.c_str(), EventWriterConstants::SQLITE_AUTO_LENGTH, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, EventWriterConstants::FINDING_BIND_ATTACK_SUB_TECHNIQUE, finding.attack_sub_technique.c_str(), EventWriterConstants::SQLITE_AUTO_LENGTH, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, EventWriterConstants::FINDING_BIND_ATTACK_REFERENCE, finding.attack_reference.c_str(), EventWriterConstants::SQLITE_AUTO_LENGTH, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, EventWriterConstants::FINDING_BIND_PREVENTION, finding.prevention.c_str(), EventWriterConstants::SQLITE_AUTO_LENGTH, SQLITE_TRANSIENT);

  sqlite3_step(stmt);
  sqlite3_finalize(stmt);
}

void EventWriter::_writeEventJson(const EVENT_RECORD &rec,
                                  const krabs::trace_context &ctx) {
  nlohmann::json j;

  try {
    //
    // 1. Basic header fields (no krabs involved)
    //
    j["ts"] = Utils::iso8601FromLargeIntegerTimestamp(rec.EventHeader.TimeStamp);
    j["raw_ts_100ns"] =
        static_cast<unsigned long long>(rec.EventHeader.TimeStamp.QuadPart);
    j["host"] = Utils::getHostName();
    uint64_t recId = 0;

// MSVC-only: compile-time check whether EVENT_HEADER has EventRecordId
#if defined(_MSC_VER)
    __if_exists(EVENT_HEADER::EventRecordId) {
      recId = static_cast<uint64_t>(rec.EventHeader.EventRecordId);
    }
#endif

    // If ETW didn't provide it (or it's 0), use our own stable counter
    if (recId == 0) {
      recId = m_fallbackEventRecordId.fetch_add(1, std::memory_order_relaxed);
    }

    j["EventRecordId"] = recId;

    j["Channel"] =
        static_cast<unsigned int>(rec.EventHeader.EventDescriptor.Channel);
    j["Level"] =
        static_cast<unsigned int>(rec.EventHeader.EventDescriptor.Level);
    j["Task"] =
        static_cast<unsigned int>(rec.EventHeader.EventDescriptor.Task);
    j["Opcode"] =
        static_cast<unsigned int>(rec.EventHeader.EventDescriptor.Opcode);
    j["Keywords"] = rec.EventHeader.EventDescriptor.Keyword;

    // Fallback EventId straight from the header (works even without krabs schema)
    j["event_id"] =
        static_cast<unsigned int>(rec.EventHeader.EventDescriptor.Id);

    j["pid"] = Utils::normUintOrNull(rec.EventHeader.ProcessId);
    j["tid"] = Utils::normUintOrNull(rec.EventHeader.ThreadId);

    if (!IsEqualGUID(rec.EventHeader.ActivityId, GUID{})) {
      j["activity"] = Utils::guidToString(rec.EventHeader.ActivityId);
    }

    //
    // 2. Provider / task / opcode names via krabs::schema (best-effort)
    //
    std::wstring providerW;
    std::wstring taskW;
    std::wstring opcodeW;
    std::wstring eventW;

    try {
      krabs::schema schema(rec, ctx.schema_locator);

      providerW = [&] {
        std::wstring p;
        try {
          p = schema.provider_name();
        } catch (const std::exception &) {
        }
        return p;
      }();

      taskW = [&] {
        std::wstring t;
        try {
          t = schema.task_name();
        } catch (const std::exception &) {
        }
        return t;
      }();

      opcodeW = [&] {
        std::wstring o;
        try {
          o = schema.opcode_name();
        } catch (const std::exception &) {
        }
        return o;
      }();

      eventW = Utils::composeEvent(schema);
      j["event"] = Utils::narrow_utf8(eventW);
      // Prefer schema event_id if available.
      j["event_id"] = schema.event_id();

      j["category"] = Utils::inferCategory(providerW, taskW);
    } catch (const krabs::could_not_find_schema &) {
      OutputDebugStringA("krabs: could_not_find_schema in _writeEventJson (names only)\n");
      // keep header-based event_id/category defaults
    } catch (const krabs::type_mismatch_assert &) {
      OutputDebugStringA("krabs: type_mismatch_assert in _writeEventJson (names only)\n");
    } catch (const std::exception &) {
      OutputDebugStringA("krabs: unknown exception in _writeEventJson (names only)\n");
    }

    std::string providerUtf8 = Utils::narrow_utf8(providerW);
    if (providerUtf8.empty()) {
      providerUtf8 = Utils::guidToString(rec.EventHeader.ProviderId);
    }
    j["provider"] = providerUtf8;
    j["task_name"] = Utils::narrow_utf8(taskW);

    //
    // 3. Properties via TDH + krabs parser (already has its own try/catch)
    //
    nlohmann::json props = nlohmann::json::object();
    _fillPropsViaTdh(props, rec, ctx);
    j["props"] = props;

    //
    // 4. Projections: proc / net / dns / file
    //
    nlohmann::json proc;
    Utils::setIfFound(proc, "name", props,
                      {"ProcessName", "ImageName", "ImageFileName"});
    Utils::setIfFound(proc, "path", props,
                      {"ImagePath", "ProcessPath", "FilePath", "ObjectName"});
    Utils::setIfFound(proc, "ppid", props,
                      {"ParentProcessId", "ParentPid", "PPID"});
    Utils::setIfFound(proc, "bitness", props, {"Bitness"});
    Utils::setIfFound(proc, "user_sid", props, {"UserSid", "SID"});
    Utils::setIfFound(proc, "integrity", props, {"IntegrityLevel", "IL"});
    Utils::setIfFound(proc, "elevated", props, {"Elevated"});
    Utils::setIfFound(proc, "signer", props,
                      {"Signer", "SignatureSigner", "Company"});
    Utils::setIfFound(proc, "sig_status", props,
                      {"SignatureStatus", "SigStatus"});
    Utils::setIfFound(proc, "sha256", props,
                      {"SHA256", "Sha256", "ImageHash"});

    if (!proc.contains("name") || !proc.contains("path")) {
      nlohmann::json fallback =
          Utils::bestEffortProcFromPid(rec.EventHeader.ProcessId);
      for (auto &kv : fallback.items()) {
        proc[kv.key()] = kv.value();
      }
    }

    if (!proc.empty()) {
      j["proc"] = std::move(proc);
    }

    if (nlohmann::json net = Utils::extractNet(props); !net.empty()) {
      j["net"] = std::move(net);
    }

    if (nlohmann::json dns = Utils::extractDns(props); !dns.empty()) {
      j["dns"] = std::move(dns);
    }

    if (nlohmann::json fil = Utils::extractFile(props, taskW, opcodeW);
        !fil.empty()) {
      j["file"] = std::move(fil);
    }
  } catch (const std::exception &) {
    OutputDebugStringA("krabs: fatal exception in _writeEventJson envelope\n");
  }

  writeEventJson(std::move(j));
}

void EventWriter::writeEventJson(nlohmann::json eventJson) {
  try {
    _enrichSigmaFields(eventJson);
    const AttackMetadata attackMetadata = AttackMetadataCatalog::forEventJson(eventJson);
    AttackMetadataCatalog::applyToJson(attackMetadata, eventJson);
    _writeOut(eventJson);
  } catch (const std::exception &) {
    OutputDebugStringA("EventWriter::writeEventJson: exception in _writeOut\n");
  }
}

void EventWriter::_writeOut(const nlohmann::json &j) {
  std::scoped_lock<std::mutex> lk(m_mtx);

  _ensureSinkOpenLocked();

  if (m_wireFormat == WireFormat::Sqlite) {
    if (!m_db) {
      if (sqlite3_open16(m_path.c_str(), &m_db) != SQLITE_OK) {
        OutputDebugStringA("_writeOut: sqlite3_open16 failed in Sqlite mode\n");
        sqlite3_close(m_db);
        m_db = nullptr;
        return;
      }
      _initSqliteSchema();
    }

    _writeToSqlite(j);
    return;
  }

  // File-based formats (JsonLines / Msgpack).
  if (!m_out.is_open()) {
    m_out.open(m_path, std::ios::out | std::ios::app | std::ios::binary);
  }

  if (!m_out) {
    OutputDebugStringA("_writeOut: failed to open output file stream\n");
    return;
  }

  if (m_wireFormat == WireFormat::Msgpack) {
    std::vector<std::uint8_t> buf = nlohmann::json::to_msgpack(j);
    if (m_lengthPrefixed) {
      const auto n = static_cast<std::uint32_t>(buf.size());
      m_out.write(reinterpret_cast<const char *>(&n), sizeof(n));
    }
    m_out.write(reinterpret_cast<const char *>(buf.data()),
                static_cast<std::streamsize>(buf.size()));
  } else { // JsonLines
    const std::string line =
        m_pretty ? (j.dump(Constants::JSON_INDENT_WIDTH) + "\n")
                 : (j.dump() + "\n");
    m_out.write(line.data(), static_cast<std::streamsize>(line.size()));
  }
}

void EventWriter::_enrichSigmaFields(nlohmann::json &j) const {
  // Use a fixed-size array to avoid heap allocation for every event
  const nlohmann::json *searchScope[EventWriterConstants::SEARCH_SCOPE_CAPACITY];
  size_t scopeSize = 0;
  searchScope[scopeSize++] = &j;

  for (const auto *cat : EventWriterConstants::EVENT_BUCKET_NAMES) {
    if (auto it = j.find(cat); it != j.end() && it->is_object()) {
      searchScope[scopeSize++] = &(*it);
    }
  }

  auto lookup = [&](const std::vector<std::string> &sources) -> const nlohmann::json * {
    for (const auto &key : sources) {
      for (size_t i = 0; i < scopeSize; ++i) {
        if (auto it = searchScope[i]->find(key); it != searchScope[i]->end() && !it->is_null()) {
          return &it.value();
        }
      }
    }
    return nullptr;
  };

  auto ensureCopy = [&](const std::string &dst,
                        const std::vector<std::string> &sources) {
    if (j.contains(dst) && !j[dst].is_null()) {
      return;
    }
    if (const nlohmann::json *v = lookup(sources)) {
      j[dst] = *v;
    }
  };

  // If the source is not a string, do nothing.
  auto ensureLowered = [&](const std::string &dst, const std::vector<std::string> &sources) {
    if (j.contains(dst) && !j[dst].is_null()) {
      return;
    }
    if (const nlohmann::json *v = lookup(sources)) {
      if (v->is_string()) {
        std::string s = v->get<std::string>();
        j[dst] = Utils::toLower(s);
      }
    }
  };

  auto basenameOf = [&](const std::string &p) {
    const auto pos = p.find_last_of("\\/");
    return (pos == std::string::npos) ? p : p.substr(pos + 1);
  };

  auto tryToDword = [&](const nlohmann::json &v, DWORD &out) {
    try {
      if (v.is_number_unsigned()) {
        out = static_cast<DWORD>(v.get<uint64_t>());
        return true;
      }
      if (v.is_number_integer()) {
        out = static_cast<DWORD>(v.get<int64_t>());
        return true;
      }
      if (v.is_string()) {
        out = static_cast<DWORD>(std::stoul(v.get<std::string>()));
        return true;
      }
    } catch (...) {
    }
    return false;
  };

  //
  // A) Host / provider / time normalization (DB columns)
  //
  ensureCopy("Computer", {"Computer", "host"});
  ensureCopy("Provider", {"Provider", "provider"});
  ensureCopy("Channel", {"Channel", "channel", "ChannelName"});
  ensureCopy("EventTime", {"EventTime", "ts"});
  ensureCopy("RuleName", {"RuleName", "Rule"});
  ensureCopy("UtcTime", {"UtcTime", "Timestamp"});

  //
  // B) Process/Image fields (Sigma canonical columns)
  //    Map nested proc.* and common ETW names into DB columns.
  //
  ensureCopy("Image", {"Image",
                       "ImagePath", "ProcessPath", "NewProcessName", "ApplicationPath",
                       "path", // proc.path / file.path (lookup scans proc/file)
                       "Process", "ProcessName",
                       "ImageFileName", "ImageName"});
  ensureCopy("SourceImage", {"SourceImage", "CallerProcessName", "SourceProcessName", "Image"});
  ensureCopy("TargetImage", {"TargetImage", "TargetProcessName", "TargetProcessPath", "Image"});

  ensureCopy("ProcessName", {"ProcessName",
                             "name", // proc.name
                             "ImageFileName", "ImageName"});

  // If ProcessName is still empty but Image exists, derive it.
  if ((!j.contains("ProcessName") || j["ProcessName"].is_null()) &&
      j.contains("Image") && j["Image"].is_string()) {
    const std::string img = j["Image"].get<std::string>();
    if (!img.empty()) {
      j["ProcessName"] = basenameOf(img);
    }
  }

  ensureCopy("CommandLine", {"CommandLine", "Commandline",
                             "CommandLineParams", "CommandLineParameters",
                             "Parameters", "Arguments"});
  ensureCopy("Commandline", {"Commandline", "CommandLine",
                             "CommandLineParams", "CommandLineParameters",
                             "Parameters", "Arguments"});
  ensureCopy("GrantedAccess", {"GrantedAccess", "DesiredAccess", "AccessMask"});

  ensureCopy("ParentImage", {"ParentImage",
                             "ParentProcessPath", "ParentImagePath", "ParentImageName",
                             "ParentProcessName"});
  ensureCopy("ParentProcessName", {"ParentProcessName",
                                   "ParentImage", "ParentImageName"});
  ensureCopy("ParentCommandLine", {"ParentCommandLine", "ParentCommandline",
                                   "ParentCommandLineParams", "ParentCommandLineParameters"});
  ensureCopy("ProcessGuid", {"ProcessGuid", "ProcessGUID"});
  ensureCopy("ParentProcessGuid", {"ParentProcessGuid", "ParentProcessGUID"});
  ensureCopy("CurrentDirectory", {"CurrentDirectory"});

  // Optional but high value: if we have PPID and ParentImage missing, resolve it.
  if ((!j.contains("ParentImage") || j["ParentImage"].is_null()) ||
      (!j.contains("ParentProcessName") || j["ParentProcessName"].is_null())) {
    if (const nlohmann::json *pp = lookup({"ParentProcessId", "ParentPid", "PPID", "ppid"})) {
      DWORD ppid = 0;
      if (tryToDword(*pp, ppid) && ppid != 0 && ppid != Constants::INVALID_PID) {
        nlohmann::json p = Utils::bestEffortProcFromPid(ppid);
        if ((!j.contains("ParentImage") || j["ParentImage"].is_null()) &&
            p.contains("path") && p["path"].is_string()) {
          j["ParentImage"] = p["path"];
        }
        if ((!j.contains("ParentProcessName") || j["ParentProcessName"].is_null()) &&
            p.contains("name") && p["name"].is_string()) {
          j["ParentProcessName"] = p["name"];
        }
      }
    }
  }

  //
  // C) Network fields (net.dst/net.dport -> DB Sigma columns)
  //
  ensureCopy("IpAddress", {"IpAddress",
                           "dst", "DestAddress", "DestIp", "RemoteIP", "DestinationIp", "dstIp"});

  ensureCopy("RemoteAddresses", {"RemoteAddresses",
                                 "dst", "DestAddress", "RemoteIP", "DestinationIp", "dstIp"});

  ensureCopy("RemotePorts", {"RemotePorts",
                             "dport", "DestPort", "RemotePort", "DestinationPort", "dstPort"});

  ensureCopy("DestinationPort", {"DestinationPort",
                                 "dport", "DestPort", "RemotePort", "dstPort"});

  ensureCopy("LocalPort", {"LocalPort", "localport", "lport", "SourcePort", "SrcPort"});
  ensureCopy("localport", {"localport", "LocalPort", "lport", "SourcePort", "SrcPort"});

  //
  // D) File/Object fields (file.path/file.op/file.status -> DB columns)
  //
  ensureCopy("ObjectName", {"ObjectName", "object_name",
                            "path", "FileName", "FilePath",
                            "TargetFilename", "TargetFileName", "TargetObject"});
  ensureCopy("object_name", {"object_name", "ObjectName",
                             "path", "FileName", "FilePath"});

  ensureCopy("Operation", {"Operation", "op", "IrpOp"});
  ensureCopy("Status", {"Status", "status", "NtStatus", "ReturnValue"});

  //
  // E) User fields (common Sigma fields)
  //
  ensureCopy("UserSid", {"UserSid", "user_sid", "SID", "SubjectUserSid", "TargetUserSid"});
  ensureCopy("SubjectUserSid", {"SubjectUserSid", "UserSid", "user_sid", "SID"});
  ensureCopy("TargetUserSid", {"TargetUserSid", "UserSid", "user_sid", "SID"});

  ensureCopy("SubjectUserName", {"SubjectUserName", "UserName", "User", "user", "AccountName"});
  ensureCopy("TargetUserName", {"TargetUserName", "TargetUser", "TargetAccountName", "AccountName"});
  ensureCopy("LogonGuid", {"LogonGuid", "LogonGUID"});
  ensureCopy("LogonId", {"LogonId"});
  ensureCopy("TerminalSessionId", {"TerminalSessionId", "SessionId"});

  //
  // F) Existing "pair sync / lowercase" compatibility (keep yours)
  //
  ensureCopy("State", {"State", "STATE"});
  ensureCopy("STATE", {"STATE", "State"});
  // Keep ObjectClas for legacy payload compatibility.
  ensureCopy("ObjectClass", {"ObjectClass", "ObjectClas"});
  // Keep ObjectClas for legacy payload compatibility.
  ensureCopy("ObjectClas", {"ObjectClas", "ObjectClass"});

  ensureLowered("domain_in_lowercase_xxx",
                {"domain_in_lowercase_xxx", "TargetDomainName", "TargetServerName", "DomainName"});
  ensureLowered("param1_lower", {"param1_lower", "Param1", "param1"});

  //
  // G) Always keep full payload for future sigma fields/debug (optional but recommended)
  //
  if (!j.contains("Payload") || j["Payload"].is_null()) {
    nlohmann::json tmp = j;
    tmp.erase("Payload");
    j["Payload"] = tmp.dump();
  }
}

void EventWriter::operator()(const EVENT_RECORD &rec, const krabs::trace_context &ctx) {
  _writeEventJson(rec, ctx);
}

void EventWriter::_ensureSinkOpenLocked() {
  if (m_wireFormat == WireFormat::Sqlite) {
    // 1. Close file stream if switching from file to DB
    if (m_out.is_open()) {
      m_out.close();
    }

    // 2. Open DB if not already open
    if (!m_db) {
      if (sqlite3_open16(m_path.c_str(), &m_db) != SQLITE_OK) {
        sqlite3_close(m_db);
        m_db = nullptr;
        throw std::runtime_error("Failed to open sqlite database");
      }

      sqlite3_busy_timeout(m_db, Constants::SQLITE_BUSY_TIMEOUT_MS);
      sqlite3_exec(m_db, "PRAGMA journal_mode=WAL;", nullptr, nullptr, nullptr);
      sqlite3_exec(m_db, "PRAGMA synchronous=NORMAL;", nullptr, nullptr, nullptr);
      _initSqliteSchema();
    }
  } else {
    // 1. Close DB if switching from DB to file
    if (m_db) {
      sqlite3_close_v2(m_db);
      m_db = nullptr;
    }

    // 2. Open file stream if not already open
    if (!m_out.is_open()) {
      m_out.open(m_path, std::ios::out | std::ios::app | std::ios::binary);
      if (!m_out) {
        OutputDebugStringA("_ensureSinkOpenLocked: failed to open output file\n");
      }
    }
  }
}



