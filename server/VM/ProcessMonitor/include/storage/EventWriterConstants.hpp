#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace EventWriterConstants {

inline constexpr int SQLITE_AUTO_LENGTH = -1;
inline constexpr int SQLITE_INDEX_BASE = 1;
inline constexpr int PRAGMA_TABLE_INFO_NAME_COLUMN_INDEX = 1;

inline constexpr std::size_t FLATTENED_FIELD_RESERVE_SIZE = 256;
inline constexpr std::size_t SEARCH_SCOPE_CAPACITY = 6;
inline constexpr std::uint16_t UINT32_BYTE_WIDTH = 4;
inline constexpr size_t BUCKET_NAMES = 5;
inline constexpr std::array<const char *, BUCKET_NAMES> EVENT_BUCKET_NAMES = {"props", "proc", "net", "dns", "file"};
inline constexpr const char *FINDINGS_DDL = R"SQL(
CREATE TABLE IF NOT EXISTS Findings (
    EventTime      DATETIME NOT NULL,
    Type           TEXT,
    Severity       INTEGER,
    Confidence     INTEGER,
    SourcePid      INTEGER,
    TargetPid      INTEGER,
    Tid            INTEGER,
    EvidenceJson   TEXT,
    AttackTactic       TEXT,
    AttackTechnique    TEXT,
    AttackSubTechnique TEXT,
    AttackReference    TEXT,
    Prevention         TEXT,
    InsertionTime  DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_findings_time ON Findings(EventTime);
CREATE INDEX IF NOT EXISTS idx_findings_type ON Findings(Type);
)SQL";

inline constexpr int PAYLOAD_BIND_EVENT_RECORD_ID = 1;
inline constexpr int PAYLOAD_BIND_JSON_TEXT = 2;

inline constexpr int FIELD_BIND_EVENT_RECORD_ID = 1;
inline constexpr int FIELD_BIND_KEY = 2;
inline constexpr int FIELD_BIND_VALUE = 3;
inline constexpr int FIELD_BIND_VALUE_TYPE = 4;

inline constexpr int FINDING_BIND_EVENT_TIME = 1;
inline constexpr int FINDING_BIND_TYPE = 2;
inline constexpr int FINDING_BIND_SEVERITY = 3;
inline constexpr int FINDING_BIND_CONFIDENCE = 4;
inline constexpr int FINDING_BIND_SOURCE_PID = 5;
inline constexpr int FINDING_BIND_TARGET_PID = 6;
inline constexpr int FINDING_BIND_TID = 7;
inline constexpr int FINDING_BIND_EVIDENCE_JSON = 8;
inline constexpr int FINDING_BIND_ATTACK_TACTIC = 9;
inline constexpr int FINDING_BIND_ATTACK_TECHNIQUE = 10;
inline constexpr int FINDING_BIND_ATTACK_SUB_TECHNIQUE = 11;
inline constexpr int FINDING_BIND_ATTACK_REFERENCE = 12;
inline constexpr int FINDING_BIND_PREVENTION = 13;

} // namespace EventWriterConstants

