#include "pch.h"
#include "SelfTest.hpp"

#include <sqlite3.h>

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <functional>
#include <iostream>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "AttackMetadata.hpp"
#include "EventWriter.hpp"
#include "ProviderProfiles.hpp"
#include "ThreadAnalysisEngine.hpp"
#include "ThreadCaches.hpp"

using ScenarioFeeder = std::function<void(
    ThreadAnalysisEngine &,
    std::chrono::time_point<std::chrono::system_clock>)>;

struct Scenario {
  std::string name;
  ScenarioFeeder feeder;
  std::map<std::string, int> expectedCounts;
};

static NormalizedEvent s_makeEvent(
    std::chrono::time_point<std::chrono::system_clock> ts,
    DWORD pid,
    DWORD tid,
    std::string provider,
    int eventId,
    std::string eventName,
    std::string taskName = {}) {
  NormalizedEvent ne{};
  ne.ts = ts;
  ne.pid = pid;
  ne.tid = tid;
  ne.provider = std::move(provider);
  ne.eventId = eventId;
  ne.fields["event"] = std::move(eventName);
  if (!taskName.empty()) {
    ne.fields["task_name"] = std::move(taskName);
  }
  ne.fields["SourcePid"] = static_cast<uint32_t>(pid);
  return ne;
}

static bool s_loadFindingCounts(
    const std::filesystem::path &dbPath,
    std::map<std::string, int> &counts,
    std::string &error) {
  sqlite3 *db = nullptr;
  if (sqlite3_open16(dbPath.c_str(), &db) != SQLITE_OK || !db) {
    error = "failed opening sqlite db";
    if (db) {
      sqlite3_close_v2(db);
    }
    return false;
  }

  sqlite3_stmt *stmt = nullptr;
  const char *sql = "SELECT Type, COUNT(*) FROM Findings GROUP BY Type";
  if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK || !stmt) {
    error = sqlite3_errmsg(db);
    if (error.find("no such table: Findings") != std::string::npos) {
      sqlite3_close_v2(db);
      return true;
    }
    if (stmt) {
      sqlite3_finalize(stmt);
    }
    sqlite3_close_v2(db);
    return false;
  }

  while (sqlite3_step(stmt) == SQLITE_ROW) {
    const unsigned char *typeTxt = sqlite3_column_text(stmt, 0);
    if (!typeTxt) {
      continue;
    }
    const int count = sqlite3_column_int(stmt, 1);
    counts[reinterpret_cast<const char *>(typeTxt)] = count;
  }

  sqlite3_finalize(stmt);
  sqlite3_close_v2(db);
  return true;
}

static bool s_validateFindingAttackMetadata(
    const std::filesystem::path &dbPath,
    const std::map<std::string, int> &expectedCounts,
    std::string &error) {
  sqlite3 *db = nullptr;
  if (sqlite3_open16(dbPath.c_str(), &db) != SQLITE_OK || !db) {
    error = "failed opening sqlite db for metadata validation";
    if (db) {
      sqlite3_close_v2(db);
    }
    return false;
  }

  sqlite3_stmt *stmt = nullptr;
  const char *sql =
      "SELECT Type, AttackTactic, AttackTechnique, AttackReference, Prevention, EvidenceJson "
      "FROM Findings";
  if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK || !stmt) {
    error = sqlite3_errmsg(db);
    if (stmt) {
      sqlite3_finalize(stmt);
    }
    sqlite3_close_v2(db);
    return false;
  }

  bool ok = true;
  while (sqlite3_step(stmt) == SQLITE_ROW) {
    const unsigned char *typeTxt = sqlite3_column_text(stmt, 0);
    const std::string type = typeTxt ? reinterpret_cast<const char *>(typeTxt) : "";
    if (type.empty() || !expectedCounts.contains(type)) {
      continue;
    }

    const auto attack = AttackMetadataCatalog::forFindingType(type);
    const unsigned char *tacticTxt = sqlite3_column_text(stmt, 1);
    const unsigned char *techniqueTxt = sqlite3_column_text(stmt, 2);
    const unsigned char *referenceTxt = sqlite3_column_text(stmt, 3);
    const unsigned char *preventionTxt = sqlite3_column_text(stmt, 4);
    const unsigned char *evidenceTxt = sqlite3_column_text(stmt, 5);

    const std::string tactic = tacticTxt ? reinterpret_cast<const char *>(tacticTxt) : "";
    const std::string technique = techniqueTxt ? reinterpret_cast<const char *>(techniqueTxt) : "";
    const std::string reference = referenceTxt ? reinterpret_cast<const char *>(referenceTxt) : "";
    const std::string prevention = preventionTxt ? reinterpret_cast<const char *>(preventionTxt) : "";
    const std::string evidence = evidenceTxt ? reinterpret_cast<const char *>(evidenceTxt) : "";

    if (tactic.empty() || technique.empty() || reference.empty() || prevention.empty()) {
      ok = false;
      error = "missing attack metadata fields in Findings";
      break;
    }
    if (!attack.technique.empty() && attack.technique != technique) {
      ok = false;
      error = "attack technique mismatch in Findings";
      break;
    }

    try {
      const auto evidenceJson = nlohmann::json::parse(evidence);
      if (!evidenceJson.is_object() ||
          !evidenceJson.contains("attack_technique") ||
          !evidenceJson["attack_technique"].is_string() ||
          evidenceJson["attack_technique"].get<std::string>().empty()) {
        ok = false;
        error = "missing attack metadata in finding evidence_json";
        break;
      }
    } catch (...) {
      ok = false;
      error = "invalid finding evidence_json format";
      break;
    }
  }

  sqlite3_finalize(stmt);
  sqlite3_close_v2(db);
  return ok;
}

static bool s_runProviderProfileStaticChecks(std::string &error) {
  const auto &providers = ProviderProfiles::getAnalystUserProviders();
  if (providers.empty()) {
    error = "analyst provider profile is empty";
    return false;
  }

  std::set<std::wstring> uniq;
  for (const auto *providerName : providers) {
    if (!providerName || !*providerName) {
      error = "analyst provider profile contains empty provider name";
      return false;
    }
    std::wstring provider(providerName);
    if (ProviderProfiles::isForbiddenProvider(provider)) {
      error = "analyst provider profile contains forbidden provider (Sysmon)";
      return false;
    }
    if (!uniq.insert(provider).second) {
      error = "analyst provider profile contains duplicates";
      return false;
    }
  }
  return true;
}

static std::optional<std::filesystem::path> s_findSigmaQueriesPath() {
  auto cur = std::filesystem::current_path();
  for (int i = 0; i < 8; ++i) {
    const auto candidate = cur / "data" / "sigma_queries.json";
    if (std::filesystem::exists(candidate)) {
      return candidate;
    }
    if (!cur.has_parent_path()) {
      break;
    }
    cur = cur.parent_path();
  }
  return std::nullopt;
}

static bool s_runSigmaCompatibilitySelfTest(std::wstring &message) {
  const auto sigmaPath = s_findSigmaQueriesPath();
  if (!sigmaPath.has_value()) {
    message = L"[self-test] SIGMA COMPAT SKIP (data/sigma_queries.json not found)";
    return true;
  }

  nlohmann::json queriesJson;
  try {
    std::ifstream in(*sigmaPath, std::ios::binary);
    if (!in) {
      message = L"[self-test] SIGMA COMPAT FAIL (cannot open sigma_queries.json)";
      return false;
    }
    in >> queriesJson;
  } catch (...) {
    message = L"[self-test] SIGMA COMPAT FAIL (failed to parse sigma_queries.json)";
    return false;
  }

  if (!queriesJson.is_array()) {
    message = L"[self-test] SIGMA COMPAT FAIL (sigma_queries.json is not array)";
    return false;
  }

  const auto dbPath =
      std::filesystem::temp_directory_path() /
      std::filesystem::path("pm_sigma_compat.sqlite");
  std::error_code ec;
  std::filesystem::remove(dbPath, ec);

  {
    EventWriter writer(dbPath.wstring(), EventWriter::WireFormat::Sqlite, false, true);
    writer.flush();
  }

  sqlite3 *db = nullptr;
  if (sqlite3_open16(dbPath.c_str(), &db) != SQLITE_OK || !db) {
    message = L"[self-test] SIGMA COMPAT FAIL (cannot open temp sqlite db)";
    if (db) {
      sqlite3_close_v2(db);
    }
    std::filesystem::remove(dbPath, ec);
    return false;
  }

  auto wrapQuery = [](const std::string &rawQuery) {
    std::string cleaned = rawQuery;
    while (!cleaned.empty() && (cleaned.back() == ';' || cleaned.back() == ' ' || cleaned.back() == '\n' || cleaned.back() == '\r' || cleaned.back() == '\t')) {
      cleaned.pop_back();
    }
    if (cleaned.empty()) {
      return std::string{};
    }
    return std::string("SELECT 1 FROM (") + cleaned + ") AS sigma_subquery LIMIT 1";
  };

  bool ok = true;
  for (const auto &entry : queriesJson) {
    if (!entry.is_string()) {
      continue;
    }

    const std::string sql = wrapQuery(entry.get<std::string>());
    if (sql.empty()) {
      continue;
    }

    sqlite3_stmt *stmt = nullptr;
    const int rc = sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
      ok = false;
      if (stmt) {
        sqlite3_finalize(stmt);
      }
      break;
    }
    sqlite3_finalize(stmt);
  }

  sqlite3_close_v2(db);
  std::filesystem::remove(dbPath, ec);
  message = ok ? L"[self-test] SIGMA COMPAT PASS" : L"[self-test] SIGMA COMPAT FAIL (query prepare error)";
  return ok;
}

static bool s_runScenario(const Scenario &scenario) {
  const auto dbPath =
      std::filesystem::temp_directory_path() /
      std::filesystem::path("pm_selftest_" + scenario.name + ".sqlite");

  std::error_code ec;
  std::filesystem::remove(dbPath, ec);

  {
    ThreadCaches caches;
    EventWriter writer(dbPath.wstring(), EventWriter::WireFormat::Sqlite, false, true);
    ThreadAnalysisEngine engine(&caches, &writer);

    const auto base = std::chrono::system_clock::time_point(std::chrono::seconds(10));
    scenario.feeder(engine, base);
    writer.flush();
  }

  std::map<std::string, int> actual;
  std::string error;
  const bool loaded = s_loadFindingCounts(dbPath, actual, error);
  if (!loaded) {
    std::filesystem::remove(dbPath, ec);
    std::wcerr << L"[self-test] " << std::wstring(scenario.name.begin(), scenario.name.end())
               << L" failed to read findings: "
               << std::wstring(error.begin(), error.end())
               << std::endl;
    return false;
  }

  bool ok = true;
  for (const auto &[type, expected] : scenario.expectedCounts) {
    const int got = actual.contains(type) ? actual[type] : 0;
    if (got != expected) {
      ok = false;
    }
  }
  for (const auto &[type, got] : actual) {
    const int expected = scenario.expectedCounts.contains(type) ? scenario.expectedCounts.at(type) : 0;
    if (got != expected) {
      ok = false;
    }
  }

  std::string metadataError;
  if (!s_validateFindingAttackMetadata(dbPath, scenario.expectedCounts, metadataError)) {
    ok = false;
    std::wcerr << L"[self-test] "
               << std::wstring(scenario.name.begin(), scenario.name.end())
               << L" attack metadata validation failed: "
               << std::wstring(metadataError.begin(), metadataError.end())
               << std::endl;
  }

  std::filesystem::remove(dbPath, ec);

  if (!ok) {
    std::wcerr << L"[self-test] "
               << std::wstring(scenario.name.begin(), scenario.name.end())
               << L" expected vs actual mismatch." << std::endl;
    std::wcerr << L"  expected:";
    for (const auto &[type, count] : scenario.expectedCounts) {
      std::wcerr << L" [" << std::wstring(type.begin(), type.end()) << L"=" << count << L"]";
    }
    std::wcerr << std::endl;

    std::wcerr << L"  actual:";
    for (const auto &[type, count] : actual) {
      std::wcerr << L" [" << std::wstring(type.begin(), type.end()) << L"=" << count << L"]";
    }
    std::wcerr << std::endl;
  }

  return ok;
}

static std::vector<Scenario> s_buildScenarios() {
  return {
      {
          "remote_thread_positive",
          [](ThreadAnalysisEngine &engine, const auto base) {
            auto access = s_makeEvent(
                base + std::chrono::seconds(0),
                1001,
                5001,
                "Microsoft-Windows-Kernel-Audit-API-Calls",
                5,
                "Info");
            access.fields["SourcePid"] = uint32_t(1001);
            access.fields["TargetPid"] = uint32_t(2001);
            access.fields["ReturnCode"] = uint32_t(0);
            engine.onEvent(access);

            auto start = s_makeEvent(
                base + std::chrono::seconds(1),
                2001,
                5002,
                "MSNT_SystemTrace",
                0,
                "Thread/Start",
                "Thread");
            start.fields["SourcePid"] = uint32_t(2001);
            start.fields["TargetPid"] = uint32_t(2001);
            start.fields["TargetTid"] = uint32_t(3001);
            start.fields["ProcessId"] = uint32_t(2001);
            start.fields["TThreadId"] = uint32_t(3001);
            engine.onEvent(start);
          },
          {{"RemoteThreadCreation", 1}},
      },
      {
          "apc_positive",
          [](ThreadAnalysisEngine &engine, const auto base) {
            auto access = s_makeEvent(
                base + std::chrono::seconds(0),
                1101,
                5101,
                "Microsoft-Windows-Kernel-Audit-API-Calls",
                6,
                "Info");
            access.fields["SourcePid"] = uint32_t(1101);
            access.fields["TargetPid"] = uint32_t(2101);
            access.fields["ReturnCode"] = uint32_t(0);
            engine.onEvent(access);

            auto apc = s_makeEvent(
                base + std::chrono::seconds(1),
                1101,
                5102,
                "Microsoft-Windows-Kernel-Audit-API-Calls",
                99,
                "QueueUserAPC");
            apc.fields["SourcePid"] = uint32_t(1101);
            apc.fields["TargetPid"] = uint32_t(2101);
            apc.fields["TargetTid"] = uint32_t(3101);
            engine.onEvent(apc);
          },
          {{"AsynchronousProcedureCallQueueing", 1}},
      },
      {
          "hijack_positive",
          [](ThreadAnalysisEngine &engine, const auto base) {
            auto start = s_makeEvent(
                base + std::chrono::seconds(0),
                2201,
                5201,
                "MSNT_SystemTrace",
                0,
                "Thread/Start",
                "Thread");
            start.fields["SourcePid"] = uint32_t(2201);
            start.fields["TargetPid"] = uint32_t(2201);
            start.fields["TargetTid"] = uint32_t(3201);
            start.fields["ProcessId"] = uint32_t(2201);
            start.fields["TThreadId"] = uint32_t(3201);
            engine.onEvent(start);

            auto suspend = s_makeEvent(
                base + std::chrono::seconds(1),
                1201,
                5202,
                "Microsoft-Windows-Kernel-Audit-API-Calls",
                200,
                "SuspendThread");
            suspend.fields["SourcePid"] = uint32_t(1201);
            suspend.fields["TargetPid"] = uint32_t(2201);
            suspend.fields["TargetTid"] = uint32_t(3201);
            engine.onEvent(suspend);

            auto context = s_makeEvent(
                base + std::chrono::seconds(2),
                1201,
                5203,
                "Microsoft-Windows-Kernel-Audit-API-Calls",
                201,
                "SetThreadContext");
            context.fields["SourcePid"] = uint32_t(1201);
            context.fields["TargetPid"] = uint32_t(2201);
            context.fields["TargetTid"] = uint32_t(3201);
            engine.onEvent(context);

            auto resume = s_makeEvent(
                base + std::chrono::seconds(3),
                1201,
                5204,
                "Microsoft-Windows-Kernel-Audit-API-Calls",
                202,
                "ResumeThread");
            resume.fields["SourcePid"] = uint32_t(1201);
            resume.fields["TargetPid"] = uint32_t(2201);
            resume.fields["TargetTid"] = uint32_t(3201);
            engine.onEvent(resume);
          },
          {{"ThreadHijackHeuristic", 1}},
      },
      {
          "negative_local_actions",
          [](ThreadAnalysisEngine &engine, const auto base) {
            auto access = s_makeEvent(
                base + std::chrono::seconds(0),
                1301,
                5301,
                "Microsoft-Windows-Kernel-Audit-API-Calls",
                6,
                "Info");
            access.fields["SourcePid"] = uint32_t(1301);
            access.fields["TargetPid"] = uint32_t(1301);
            access.fields["ReturnCode"] = uint32_t(0);
            engine.onEvent(access);

            auto apc = s_makeEvent(
                base + std::chrono::seconds(1),
                1301,
                5302,
                "Microsoft-Windows-Kernel-Audit-API-Calls",
                99,
                "QueueUserAPC");
            apc.fields["SourcePid"] = uint32_t(1301);
            apc.fields["TargetPid"] = uint32_t(1301);
            apc.fields["TargetTid"] = uint32_t(3301);
            engine.onEvent(apc);

            auto start = s_makeEvent(
                base + std::chrono::seconds(2),
                1301,
                5303,
                "MSNT_SystemTrace",
                0,
                "Thread/Start",
                "Thread");
            start.fields["SourcePid"] = uint32_t(1301);
            start.fields["TargetPid"] = uint32_t(1301);
            start.fields["TargetTid"] = uint32_t(3301);
            start.fields["ProcessId"] = uint32_t(1301);
            start.fields["TThreadId"] = uint32_t(3301);
            engine.onEvent(start);

            auto suspend = s_makeEvent(
                base + std::chrono::seconds(3),
                1301,
                5304,
                "Microsoft-Windows-Kernel-Audit-API-Calls",
                200,
                "SuspendThread");
            suspend.fields["SourcePid"] = uint32_t(1301);
            suspend.fields["TargetPid"] = uint32_t(1301);
            suspend.fields["TargetTid"] = uint32_t(3301);
            engine.onEvent(suspend);

            auto context = s_makeEvent(
                base + std::chrono::seconds(4),
                1301,
                5305,
                "Microsoft-Windows-Kernel-Audit-API-Calls",
                201,
                "SetThreadContext");
            context.fields["SourcePid"] = uint32_t(1301);
            context.fields["TargetPid"] = uint32_t(1301);
            context.fields["TargetTid"] = uint32_t(3301);
            engine.onEvent(context);

            auto resume = s_makeEvent(
                base + std::chrono::seconds(5),
                1301,
                5306,
                "Microsoft-Windows-Kernel-Audit-API-Calls",
                202,
                "ResumeThread");
            resume.fields["SourcePid"] = uint32_t(1301);
            resume.fields["TargetPid"] = uint32_t(1301);
            resume.fields["TargetTid"] = uint32_t(3301);
            engine.onEvent(resume);
          },
          {},
      },
      {
          "negative_incomplete_sequence",
          [](ThreadAnalysisEngine &engine, const auto base) {
            auto start = s_makeEvent(
                base + std::chrono::seconds(0),
                2401,
                5401,
                "MSNT_SystemTrace",
                0,
                "Thread/Start",
                "Thread");
            start.fields["SourcePid"] = uint32_t(2401);
            start.fields["TargetPid"] = uint32_t(2401);
            start.fields["TargetTid"] = uint32_t(3401);
            start.fields["ProcessId"] = uint32_t(2401);
            start.fields["TThreadId"] = uint32_t(3401);
            engine.onEvent(start);

            auto suspend = s_makeEvent(
                base + std::chrono::seconds(1),
                1401,
                5402,
                "Microsoft-Windows-Kernel-Audit-API-Calls",
                200,
                "SuspendThread");
            suspend.fields["SourcePid"] = uint32_t(1401);
            suspend.fields["TargetPid"] = uint32_t(2401);
            suspend.fields["TargetTid"] = uint32_t(3401);
            engine.onEvent(suspend);

            auto resume = s_makeEvent(
                base + std::chrono::seconds(2),
                1401,
                5403,
                "Microsoft-Windows-Kernel-Audit-API-Calls",
                202,
                "ResumeThread");
            resume.fields["SourcePid"] = uint32_t(1401);
            resume.fields["TargetPid"] = uint32_t(2401);
            resume.fields["TargetTid"] = uint32_t(3401);
            engine.onEvent(resume);
          },
          {},
      },
      {
          "negative_stale",
          [](ThreadAnalysisEngine &engine, const auto base) {
            auto access = s_makeEvent(
                base + std::chrono::seconds(0),
                1501,
                5501,
                "Microsoft-Windows-Kernel-Audit-API-Calls",
                5,
                "Info");
            access.fields["SourcePid"] = uint32_t(1501);
            access.fields["TargetPid"] = uint32_t(2501);
            access.fields["ReturnCode"] = uint32_t(0);
            engine.onEvent(access);

            auto staleStart = s_makeEvent(
                base + std::chrono::seconds(12),
                2501,
                5502,
                "MSNT_SystemTrace",
                0,
                "Thread/Start",
                "Thread");
            staleStart.fields["SourcePid"] = uint32_t(2501);
            staleStart.fields["TargetPid"] = uint32_t(2501);
            staleStart.fields["TargetTid"] = uint32_t(3501);
            staleStart.fields["ProcessId"] = uint32_t(2501);
            staleStart.fields["TThreadId"] = uint32_t(3501);
            engine.onEvent(staleStart);

            auto owner = s_makeEvent(
                base + std::chrono::seconds(0),
                2601,
                5503,
                "MSNT_SystemTrace",
                0,
                "Thread/Start",
                "Thread");
            owner.fields["SourcePid"] = uint32_t(2601);
            owner.fields["TargetPid"] = uint32_t(2601);
            owner.fields["TargetTid"] = uint32_t(3601);
            owner.fields["ProcessId"] = uint32_t(2601);
            owner.fields["TThreadId"] = uint32_t(3601);
            engine.onEvent(owner);

            auto suspend = s_makeEvent(
                base + std::chrono::seconds(1),
                1601,
                5504,
                "Microsoft-Windows-Kernel-Audit-API-Calls",
                200,
                "SuspendThread");
            suspend.fields["SourcePid"] = uint32_t(1601);
            suspend.fields["TargetPid"] = uint32_t(2601);
            suspend.fields["TargetTid"] = uint32_t(3601);
            engine.onEvent(suspend);

            auto context = s_makeEvent(
                base + std::chrono::seconds(14),
                1601,
                5505,
                "Microsoft-Windows-Kernel-Audit-API-Calls",
                201,
                "SetThreadContext");
            context.fields["SourcePid"] = uint32_t(1601);
            context.fields["TargetPid"] = uint32_t(2601);
            context.fields["TargetTid"] = uint32_t(3601);
            engine.onEvent(context);

            auto resume = s_makeEvent(
                base + std::chrono::seconds(15),
                1601,
                5506,
                "Microsoft-Windows-Kernel-Audit-API-Calls",
                202,
                "ResumeThread");
            resume.fields["SourcePid"] = uint32_t(1601);
            resume.fields["TargetPid"] = uint32_t(2601);
            resume.fields["TargetTid"] = uint32_t(3601);
            engine.onEvent(resume);
          },
          {},
      },
      {
          "duplicate_suppression",
          [](ThreadAnalysisEngine &engine, const auto base) {
            auto access = s_makeEvent(
                base + std::chrono::seconds(0),
                1701,
                5701,
                "Microsoft-Windows-Kernel-Audit-API-Calls",
                6,
                "Info");
            access.fields["SourcePid"] = uint32_t(1701);
            access.fields["TargetPid"] = uint32_t(2701);
            access.fields["ReturnCode"] = uint32_t(0);
            engine.onEvent(access);

            auto apc1 = s_makeEvent(
                base + std::chrono::seconds(1),
                1701,
                5702,
                "Microsoft-Windows-Kernel-Audit-API-Calls",
                99,
                "NtQueueApcThread");
            apc1.fields["SourcePid"] = uint32_t(1701);
            apc1.fields["TargetPid"] = uint32_t(2701);
            apc1.fields["TargetTid"] = uint32_t(3701);
            engine.onEvent(apc1);

            auto apc2 = s_makeEvent(
                base + std::chrono::seconds(2),
                1701,
                5703,
                "Microsoft-Windows-Kernel-Audit-API-Calls",
                99,
                "NtQueueApcThread");
            apc2.fields["SourcePid"] = uint32_t(1701);
            apc2.fields["TargetPid"] = uint32_t(2701);
            apc2.fields["TargetTid"] = uint32_t(3701);
            engine.onEvent(apc2);
          },
	          {{"AsynchronousProcedureCallQueueing", 1}},
	      },
	      {
	          "threat_intel_injection_positive",
	          [](ThreadAnalysisEngine &engine, const auto base) {
	            auto ti = s_makeEvent(
	                base + std::chrono::seconds(0),
	                1801,
	                5801,
	                "Microsoft-Windows-Threat-Intelligence",
	                501,
	                "CreateRemoteThread");
	            ti.fields["SourcePid"] = uint32_t(1801);
	            ti.fields["TargetPid"] = uint32_t(2801);
	            ti.fields["TargetTid"] = uint32_t(3801);
	            engine.onEvent(ti);
	          },
	          {{"ThreatIntelInjection", 1}},
	      },
	      {
	          "runkey_persistence_positive",
	          [](ThreadAnalysisEngine &engine, const auto base) {
	            auto reg = s_makeEvent(
	                base + std::chrono::seconds(0),
	                1901,
	                5901,
	                "Microsoft-Windows-Kernel-Registry",
	                700,
	                "SetValue");
	            reg.fields["SourcePid"] = uint32_t(1901);
	            reg.fields["ObjectName"] = std::string("\\REGISTRY\\MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater");
	            engine.onEvent(reg);
	          },
	          {{"RegistryRunKeyPersistence", 1}},
	      },
	      {
	          "scheduled_task_persistence_positive",
	          [](ThreadAnalysisEngine &engine, const auto base) {
	            auto task = s_makeEvent(
	                base + std::chrono::seconds(0),
	                2001,
	                6001,
	                "Microsoft-Windows-TaskScheduler",
	                106,
	                "Task Created");
	            task.fields["SourcePid"] = uint32_t(2001);
	            task.fields["TaskName"] = std::string("\\Microsoft\\Windows\\Updater\\Maintenance");
	            engine.onEvent(task);
	          },
	          {{"ScheduledTaskPersistence", 1}},
	      },
	      {
	          "service_persistence_positive",
	          [](ThreadAnalysisEngine &engine, const auto base) {
	            auto svc = s_makeEvent(
	                base + std::chrono::seconds(0),
	                2101,
	                6101,
	                "Microsoft-Windows-Services",
	                7045,
	                "CreateService");
	            svc.fields["SourcePid"] = uint32_t(2101);
	            svc.fields["ObjectName"] = std::string("\\Registry\\Machine\\System\\CurrentControlSet\\Services\\MalService");
	            svc.fields["ServiceName"] = std::string("MalService");
	            engine.onEvent(svc);
	          },
	          {{"ServicePersistence", 1}},
	      },
	      {
	          "lsass_credential_access_positive",
	          [](ThreadAnalysisEngine &engine, const auto base) {
	            auto access = s_makeEvent(
	                base + std::chrono::seconds(0),
	                2201,
	                6201,
	                "Microsoft-Windows-Kernel-Audit-API-Calls",
	                5,
	                "OpenProcess");
	            access.fields["SourcePid"] = uint32_t(2201);
	            access.fields["TargetPid"] = uint32_t(500);
	            access.fields["TargetImage"] = std::string("C:\\Windows\\System32\\lsass.exe");
	            access.fields["DesiredAccess"] = uint64_t(0x0010);
	            access.fields["ReturnCode"] = uint32_t(0);
	            engine.onEvent(access);
	          },
	          {{"LsassCredentialAccess", 1}},
	      },
	  };
}

int RunProcessMonitorSelfTest() {
  std::string providerProfileError;
  if (!s_runProviderProfileStaticChecks(providerProfileError)) {
    std::wcerr << L"[self-test] FAIL provider_profile_checks: "
               << std::wstring(providerProfileError.begin(), providerProfileError.end())
               << std::endl;
    return EXIT_FAILURE;
  }
  std::wcout << L"[self-test] PASS provider_profile_checks" << std::endl;

  const auto scenarios = s_buildScenarios();
  int failed = 0;

  for (const auto &scenario : scenarios) {
    if (s_runScenario(scenario)) {
      std::wcout << L"[self-test] PASS "
                 << std::wstring(scenario.name.begin(), scenario.name.end())
                 << std::endl;
    } else {
      std::wcout << L"[self-test] FAIL "
                 << std::wstring(scenario.name.begin(), scenario.name.end())
                 << std::endl;
      ++failed;
    }
  }

  std::wstring sigmaMessage;
  if (s_runSigmaCompatibilitySelfTest(sigmaMessage)) {
    std::wcout << sigmaMessage << std::endl;
  } else {
    std::wcerr << sigmaMessage << std::endl;
    ++failed;
  }

  if (failed == 0) {
    std::wcout << L"[self-test] all scenarios passed" << std::endl;
    return EXIT_SUCCESS;
  }

  std::wcerr << L"[self-test] failures: " << failed << std::endl;
  return EXIT_FAILURE;
}



