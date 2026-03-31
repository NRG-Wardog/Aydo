#include "ProcessMonitor.hpp"
#include <initializer_list>
#include <limits>
#include <optional>
#include <string_view>
#include <thread>
#include <windows.h>
#include <winevt.h>
#include <algorithm>
#include <iostream>
#include <sstream>
#include <unordered_set>

#include "Deadline.hpp"
#include "ProcessMonitorConstants.hpp"
#include "SafeKrabsParser.hpp"
#include "Utils.hpp"

namespace {
struct ParsedSysmonEvent {
  std::string provider;
  std::string channel;
  std::string computer;
  std::string timeCreated;
  std::string eventName;
  std::string taskName;
  std::string keywords;
  std::uint64_t recordId = 0;
  DWORD executionPid = 0;
  DWORD executionTid = 0;
  DWORD logicalPid = 0;
  DWORD logicalTid = 0;
  unsigned int eventId = 0;
  unsigned int level = 0;
  unsigned int task = 0;
  unsigned int opcode = 0;
  nlohmann::json props = nlohmann::json::object();
  NormalizedEvent normalized;
};

std::wstring s_xmlUnescape(std::wstring_view input) {
  std::wstring out;
  out.reserve(input.size());

  for (size_t i = 0; i < input.size(); ++i) {
    if (input[i] != L'&') {
      out.push_back(input[i]);
      continue;
    }

    const size_t semi = input.find(L';', i + 1);
    if (semi == std::wstring_view::npos) {
      out.push_back(input[i]);
      continue;
    }

    const std::wstring_view entity = input.substr(i + 1, semi - i - 1);
    if (entity == L"amp") {
      out.push_back(L'&');
    } else if (entity == L"lt") {
      out.push_back(L'<');
    } else if (entity == L"gt") {
      out.push_back(L'>');
    } else if (entity == L"apos") {
      out.push_back(L'\'');
    } else if (entity == L"quot") {
      out.push_back(L'"');
    } else if (entity.starts_with(L"#x")) {
      try {
        const auto code = static_cast<wchar_t>(std::stoul(std::wstring(entity.substr(2)), nullptr, 16));
        out.push_back(code);
      } catch (...) {
        out.append(input.substr(i, semi - i + 1));
      }
    } else if (entity.starts_with(L"#")) {
      try {
        const auto code = static_cast<wchar_t>(std::stoul(std::wstring(entity.substr(1)), nullptr, 10));
        out.push_back(code);
      } catch (...) {
        out.append(input.substr(i, semi - i + 1));
      }
    } else {
      out.append(input.substr(i, semi - i + 1));
    }

    i = semi;
  }

  return out;
}

std::optional<std::wstring> s_findXmlAttribute(std::wstring_view xml,
                                               std::wstring_view elementName,
                                               std::wstring_view attributeName) {
  const std::wstring elementNeedle = L"<" + std::wstring(elementName);
  size_t elementPos = xml.find(elementNeedle);
  if (elementPos == std::wstring_view::npos) {
    return std::nullopt;
  }

  const size_t elementEnd = xml.find(L'>', elementPos);
  if (elementEnd == std::wstring_view::npos) {
    return std::nullopt;
  }

  const std::wstring attrNeedle = std::wstring(attributeName) + L"=";
  size_t attrPos = xml.find(attrNeedle, elementPos);
  if (attrPos == std::wstring_view::npos || attrPos >= elementEnd) {
    return std::nullopt;
  }

  const size_t quotePos = attrPos + attrNeedle.size();
  if (quotePos >= xml.size()) {
    return std::nullopt;
  }

  const wchar_t quote = xml[quotePos];
  const size_t valueStart = quotePos + 1;
  const size_t valueEnd = xml.find(quote, valueStart);
  if (valueEnd == std::wstring_view::npos || valueEnd > elementEnd) {
    return std::nullopt;
  }

  return s_xmlUnescape(xml.substr(valueStart, valueEnd - valueStart));
}

std::optional<std::wstring> s_findXmlElementText(std::wstring_view xml,
                                                 std::wstring_view elementName) {
  const std::wstring openNeedle = L"<" + std::wstring(elementName) + L">";
  const std::wstring closeNeedle = L"</" + std::wstring(elementName) + L">";

  const size_t openPos = xml.find(openNeedle);
  if (openPos == std::wstring_view::npos) {
    return std::nullopt;
  }

  const size_t valueStart = openPos + openNeedle.size();
  const size_t closePos = xml.find(closeNeedle, valueStart);
  if (closePos == std::wstring_view::npos) {
    return std::nullopt;
  }

  return s_xmlUnescape(xml.substr(valueStart, closePos - valueStart));
}

template <typename UInt>
std::optional<UInt> s_parseUnsigned(std::string_view text, int base = 10) {
  if (text.empty()) {
    return std::nullopt;
  }

  try {
    size_t consumed = 0;
    const auto parsed = std::stoull(std::string(text), &consumed, base);
    if (consumed != text.size()) {
      return std::nullopt;
    }
    if (parsed > static_cast<unsigned long long>(std::numeric_limits<UInt>::max())) {
      return std::nullopt;
    }
    return static_cast<UInt>(parsed);
  } catch (...) {
    return std::nullopt;
  }
}

std::string s_sysmonEventName(unsigned eventId) {
  switch (eventId) {
  case 1:
    return "Process Create";
  case 3:
    return "Network Connection";
  case 5:
    return "Process Terminate";
  case 8:
    return "CreateRemoteThread";
  case 10:
    return "Process Access";
  case 11:
    return "File Create";
  case 12:
  case 13:
  case 14:
    return "Registry Event";
  case 17:
  case 18:
    return "Pipe Event";
  case 22:
    return "Dns Query";
  case 255:
    return "Error Report";
  default:
    return "Sysmon Event";
  }
}

std::optional<std::wstring> s_renderEventXml(EVT_HANDLE eventHandle) {
  DWORD bufferUsed = 0;
  DWORD propertyCount = 0;
  if (!EvtRender(nullptr, eventHandle, EvtRenderEventXml, 0, nullptr, &bufferUsed, &propertyCount)) {
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
      return std::nullopt;
    }
  }

  std::wstring xml(bufferUsed / sizeof(wchar_t), L'\0');
  if (!EvtRender(nullptr, eventHandle, EvtRenderEventXml, bufferUsed, xml.data(), &bufferUsed, &propertyCount)) {
    return std::nullopt;
  }

  if (!xml.empty() && xml.back() == L'\0') {
    xml.pop_back();
  }
  return xml;
}

void s_setJsonField(nlohmann::json &props,
                    const std::string &name,
                    const std::string &value) {
  static const std::unordered_set<std::string> s_hexFields = {
      "GrantedAccess",
      "DesiredAccess",
      "LogonId",
      "SourceThreadId",
      "NewThreadId",
      "QueryStatus",
  };
  static const std::unordered_set<std::string> s_u32Fields = {
      "ProcessId",
      "ParentProcessId",
      "SourceProcessId",
      "TargetProcessId",
      "SourcePid",
      "TargetPid",
      "SourceThreadId",
      "TargetThreadId",
      "NewThreadId",
      "TerminalSessionId",
      "QueryStatus",
  };

  if (s_hexFields.contains(name)) {
    if (auto parsed = s_parseUnsigned<std::uint64_t>(value, 0)) {
      props[name] = *parsed;
      return;
    }
  }

  if (s_u32Fields.contains(name)) {
    if (auto parsed = s_parseUnsigned<std::uint32_t>(value, 10)) {
      props[name] = *parsed;
      return;
    }
  }

  props[name] = value;
}

std::optional<ParsedSysmonEvent> s_parseSysmonEventXml(const std::wstring &xml) {
  ParsedSysmonEvent parsed;
  parsed.provider = Utils::narrow_utf8(s_findXmlAttribute(xml, L"Provider", L"Name").value_or(std::wstring(ProcessMonitorConstants::SYSMON_PROVIDER_NAME)));
  parsed.channel = Utils::narrow_utf8(s_findXmlElementText(xml, L"Channel").value_or(std::wstring(ProcessMonitorConstants::SYSMON_CHANNEL_NAME)));
  parsed.computer = Utils::narrow_utf8(s_findXmlElementText(xml, L"Computer").value_or(L""));
  parsed.timeCreated = Utils::narrow_utf8(s_findXmlAttribute(xml, L"TimeCreated", L"SystemTime").value_or(L""));
  parsed.recordId = s_parseUnsigned<std::uint64_t>(Utils::narrow_utf8(s_findXmlElementText(xml, L"EventRecordID").value_or(L"")), 10).value_or(0);
  parsed.eventId = s_parseUnsigned<unsigned>(Utils::narrow_utf8(s_findXmlElementText(xml, L"EventID").value_or(L"")), 10).value_or(0);
  parsed.level = s_parseUnsigned<unsigned>(Utils::narrow_utf8(s_findXmlElementText(xml, L"Level").value_or(L"")), 10).value_or(0);
  parsed.task = s_parseUnsigned<unsigned>(Utils::narrow_utf8(s_findXmlElementText(xml, L"Task").value_or(L"")), 10).value_or(0);
  parsed.opcode = s_parseUnsigned<unsigned>(Utils::narrow_utf8(s_findXmlElementText(xml, L"Opcode").value_or(L"")), 10).value_or(0);
  parsed.keywords = Utils::narrow_utf8(s_findXmlElementText(xml, L"Keywords").value_or(L""));
  parsed.executionPid = s_parseUnsigned<DWORD>(Utils::narrow_utf8(s_findXmlAttribute(xml, L"Execution", L"ProcessID").value_or(L"")), 10).value_or(0);
  parsed.executionTid = s_parseUnsigned<DWORD>(Utils::narrow_utf8(s_findXmlAttribute(xml, L"Execution", L"ThreadID").value_or(L"")), 10).value_or(0);
  parsed.eventName = s_sysmonEventName(parsed.eventId);
  parsed.taskName = parsed.eventName;

  size_t pos = 0;
  while ((pos = xml.find(L"<Data ", pos)) != std::wstring::npos) {
    const size_t dataEnd = xml.find(L"</Data>", pos);
    if (dataEnd == std::wstring::npos) {
      break;
    }

    const auto name = s_findXmlAttribute(xml.substr(pos, dataEnd - pos + 7), L"Data", L"Name");
    const size_t valueStart = xml.find(L'>', pos);
    if (!name.has_value() || valueStart == std::wstring::npos || valueStart > dataEnd) {
      pos = dataEnd + 7;
      continue;
    }

    const std::wstring value = s_xmlUnescape(xml.substr(valueStart + 1, dataEnd - valueStart - 1));
    s_setJsonField(parsed.props, Utils::narrow_utf8(*name), Utils::narrow_utf8(value));
    pos = dataEnd + 7;
  }

  auto propU32 = [&](std::initializer_list<const char *> keys) -> std::optional<DWORD> {
    for (const auto *key : keys) {
      auto it = parsed.props.find(key);
      if (it == parsed.props.end()) {
        continue;
      }
      if (it->is_number_unsigned()) {
        return static_cast<DWORD>(it->get<std::uint64_t>());
      }
      if (it->is_number_integer()) {
        return static_cast<DWORD>(it->get<std::int64_t>());
      }
      if (it->is_string()) {
        if (auto parsedValue = s_parseUnsigned<DWORD>(it->get<std::string>(), 10)) {
          return *parsedValue;
        }
      }
    }
    return std::nullopt;
  };
  auto propU64 = [&](std::initializer_list<const char *> keys) -> std::optional<std::uint64_t> {
    for (const auto *key : keys) {
      auto it = parsed.props.find(key);
      if (it == parsed.props.end()) {
        continue;
      }
      if (it->is_number_unsigned()) {
        return it->get<std::uint64_t>();
      }
      if (it->is_number_integer()) {
        const auto value = it->get<std::int64_t>();
        if (value >= 0) {
          return static_cast<std::uint64_t>(value);
        }
      }
      if (it->is_string()) {
        if (auto parsedValue = s_parseUnsigned<std::uint64_t>(it->get<std::string>(), 0)) {
          return *parsedValue;
        }
      }
    }
    return std::nullopt;
  };
  auto propString = [&](std::initializer_list<const char *> keys) -> std::optional<std::string> {
    for (const auto *key : keys) {
      auto it = parsed.props.find(key);
      if (it == parsed.props.end()) {
        continue;
      }
      if (it->is_string()) {
        return it->get<std::string>();
      }
    }
    return std::nullopt;
  };

  parsed.logicalPid = propU32({"SourceProcessId", "ProcessId", "TargetProcessId"}).value_or(parsed.executionPid);
  parsed.logicalTid = propU32({"SourceThreadId", "NewThreadId", "TargetThreadId"}).value_or(parsed.executionTid);

  parsed.normalized.ts = std::chrono::system_clock::now();
  parsed.normalized.pid = parsed.logicalPid;
  parsed.normalized.tid = parsed.logicalTid;
  parsed.normalized.provider = parsed.provider;
  parsed.normalized.eventId = static_cast<int>(parsed.eventId);
  parsed.normalized.fields["SourcePid"] = static_cast<std::uint32_t>(parsed.logicalPid);

  if (auto value = propU32({"SourceProcessId"})) {
    parsed.normalized.fields["SourcePid"] = static_cast<std::uint32_t>(*value);
  }
  if (auto value = propU32({"TargetProcessId", "ProcessId"})) {
    parsed.normalized.fields["TargetPid"] = static_cast<std::uint32_t>(*value);
  }
  if (auto value = propU32({"NewThreadId", "TargetThreadId"})) {
    parsed.normalized.fields["TargetTid"] = static_cast<std::uint32_t>(*value);
    parsed.normalized.fields["TThreadId"] = static_cast<std::uint32_t>(*value);
  }
  if (auto value = propU32({"ProcessId"})) {
    parsed.normalized.fields["ProcessId"] = static_cast<std::uint32_t>(*value);
  }
  if (auto value = propU64({"GrantedAccess", "DesiredAccess"})) {
    parsed.normalized.fields["GrantedAccess"] = *value;
    parsed.normalized.fields["DesiredAccess"] = *value;
  }
  if (auto value = propString({"Image"})) {
    parsed.normalized.fields["Image"] = *value;
  }
  if (auto value = propString({"SourceImage"})) {
    parsed.normalized.fields["SourceImage"] = *value;
  }
  if (auto value = propString({"TargetImage"})) {
    parsed.normalized.fields["TargetImage"] = *value;
  }
  if (auto value = propString({"TargetObject"})) {
    parsed.normalized.fields["ObjectName"] = *value;
  } else if (auto value = propString({"ObjectName"})) {
    parsed.normalized.fields["ObjectName"] = *value;
  }
  if (auto value = propString({"TaskName"})) {
    parsed.normalized.fields["TaskName"] = *value;
  }
  if (auto value = propString({"ServiceName"})) {
    parsed.normalized.fields["ServiceName"] = *value;
  }
  if (auto value = propString({"EventType"})) {
    parsed.normalized.fields["EventType"] = *value;
  }

  return parsed;
}

std::optional<std::uint64_t> s_getLatestSysmonRecordId() {
  EVT_HANDLE query = EvtQuery(nullptr,
                              ProcessMonitorConstants::SYSMON_CHANNEL_NAME.data(),
                              L"*",
                              EvtQueryChannelPath | EvtQueryReverseDirection);
  if (!query) {
    return std::nullopt;
  }

  EVT_HANDLE eventHandle = nullptr;
  DWORD returned = 0;
  if (!EvtNext(query, 1, &eventHandle, 0, 0, &returned) || returned == 0) {
    EvtClose(query);
    return 0;
  }

  std::optional<std::uint64_t> recordId;
  if (const auto xml = s_renderEventXml(eventHandle); xml.has_value()) {
    if (const auto parsed = s_parseSysmonEventXml(*xml); parsed.has_value()) {
      recordId = parsed->recordId;
    }
  }

  EvtClose(eventHandle);
  EvtClose(query);
  return recordId;
}
} // namespace

static std::wstring s_joinPids(const std::set<DWORD> &pids) {
  std::wstring out;
  bool first = true;
  for (const DWORD pid : pids) {
    if (!first) {
      out += ProcessMonitorConstants::PID_SEPARATOR;
    }
    out += std::to_wstring(pid);
    first = false;
  }
  return out;
}

ProcessMonitor::ProcessMonitor(const std::wstring &exeName, const std::wstring &sessionNameKernel, const std::wstring &sessionNameUser, const std::wstring &outPath) noexcept
    : m_user{sessionNameUser}
    , m_kernel{sessionNameKernel}
    , m_threads{}
    , m_caches{}
    , m_writer(std::make_unique<EventWriter>(outPath, EventWriter::WireFormat::Sqlite, false, true))
    , m_threadAnalysis(&m_caches.thread, m_writer.get())
    , m_targetExeName(exeName) {
  m_targetPids = findPidsByName(exeName);
}
ProcessMonitor::ProcessMonitor(const std::set<DWORD> &initialPids, const std::wstring &sessionNameKernel, const std::wstring &sessionNameUser, std::wstring outPath) noexcept
    : m_user{sessionNameUser}
    , m_kernel{sessionNameKernel}
    , m_threads{}
    , m_caches{}
    , m_writer(std::make_unique<EventWriter>(outPath, EventWriter::WireFormat::Sqlite, false, true))
    , m_threadAnalysis(&m_caches.thread, m_writer.get())
    , m_targetExeName(std::nullopt) {
  m_targetPids = initialPids;
}

std::set<DWORD> ProcessMonitor::_targetPidsSnapshot() const {
  std::scoped_lock lk(m_targetPidsMtx);
  return m_targetPids;
}

void ProcessMonitor::_refreshTargetPidsIfNeeded(bool forceRefresh,
                                                bool announceChanges) {
  if (!m_targetExeName.has_value()) {
    return;
  }

  const auto now = std::chrono::steady_clock::now();
  {
    std::scoped_lock lk(m_targetPidsMtx);
    if (!forceRefresh &&
        m_lastTargetPidRefresh.time_since_epoch().count() != 0 &&
        (now - m_lastTargetPidRefresh) < ProcessMonitorConstants::TARGET_PID_REFRESH_INTERVAL) {
      return;
    }
    m_lastTargetPidRefresh = now;
  }

  const auto latest = findPidsByName(*m_targetExeName);
  std::set<DWORD> previous;
  bool changed = false;
  {
    std::scoped_lock lk(m_targetPidsMtx);
    previous = m_targetPids;
    if (latest != m_targetPids) {
      m_targetPids = latest;
      changed = true;
    }
  }

  if (announceChanges && changed) {
    std::wcout << ProcessMonitorConstants::PROCESS_LIST_PREFIX
               << (latest.empty() ? std::wstring(ProcessMonitorConstants::PROCESS_NONE_VALUE)
                                  : s_joinPids(latest))
               << std::endl;

    for (const DWORD pid : previous) {
      if (!latest.contains(pid)) {
        std::wcout << L"process <" << pid << ProcessMonitorConstants::PROCESS_STOPPED_SUFFIX << std::endl;
      }
    }

    for (const DWORD pid : latest) {
      if (!previous.contains(pid)) {
        std::wcout << L"process <" << pid << ProcessMonitorConstants::PROCESS_STARTED_SUFFIX << std::endl;
      }
    }
  }
}

static std::string s_guidToString(const GUID &g) {
  wchar_t buf[64] = {};
  const int n = StringFromGUID2(g, buf, static_cast<int>(std::size(buf)));
  if (n <= 0) {
    return "<guid_error>";
  }
  return Utils::narrow_utf8(buf);
}

void ProcessMonitor::_recordProviderCount(const GUID &provider) {
  std::scoped_lock lk(m_providerCountsMtx);
  m_providerCounts[provider] += 1;
}

void ProcessMonitor::_emitProviderSummary() const {
  std::scoped_lock lk(m_providerCountsMtx);
  if (m_providerCounts.empty()) {
    return;
  }
  std::ostringstream oss;
  oss << "ProcessMonitor provider summary:";
  for (const auto &[gid, cnt] : m_providerCounts) {
    oss << " [" << s_guidToString(gid) << "]=" << cnt;
  }
  oss << "\n";
  OutputDebugStringA(oss.str().c_str());
  std::cout << oss.str();
}

bool ProcessMonitor::_pidAllowed(const EVENT_RECORD &record,
                                 const krabs::trace_context &ctx) {
  _refreshTargetPidsIfNeeded(false, false);

  // Policy: ingest all Sysmon events when Sysmon provider is active.
  if (InlineIsEqualGUID(record.EventHeader.ProviderId, ProcessMonitorConstants::SYSMON_PROVIDER_GUID)) {
    return true;
  }

  // Fallback by provider name if GUID match is unavailable.
  try {
    krabs::schema schema(record, ctx.schema_locator);
    try {
      const auto providerName = schema.provider_name();
      if (providerName != nullptr &&
          _wcsicmp(providerName, ProcessMonitorConstants::SYSMON_PROVIDER_NAME.data()) == 0) {
        return true;
      }
    } catch (...) {
    }
  } catch (...) {
  }

  const auto targetPids = _targetPidsSnapshot();

  if (targetPids.empty()) {
    // When matching by executable name, never fall back to "allow all" if no live match exists.
    return !m_targetExeName.has_value();
  }

  auto inTargets = [&targetPids](DWORD pid) {
    return pid != ProcessMonitorConstants::INVALID_PID && targetPids.contains(pid);
  };

  if (inTargets(record.EventHeader.ProcessId)) {
    return true;
  }

  try {
    krabs::schema schema(record, ctx.schema_locator);
    SafeKrabsParserSession parser(schema);

    auto tryU32 = [&](const wchar_t *name) -> std::optional<uint32_t> {
      return parser.tryParse<uint32_t>(name);
    };

    for (const auto *field : {L"SourcePid", L"SourceProcessId", L"TargetPid", L"TargetProcessId", L"ProcessId"}) {
      if (auto v = tryU32(field); v && inTargets(static_cast<DWORD>(*v))) {
        return true;
      }
      if (parser.isPoisoned()) {
        break;
      }
    }
  } catch (...) {
  }

  return false;
}

void ProcessMonitor::_analyzeRecord(const EVENT_RECORD &record,
                                    const krabs::trace_context &ctx) {
  std::scoped_lock lk(m_analysisMtx);

  NormalizedEvent ne{};
  ne.ts = std::chrono::system_clock::now();
  ne.pid = record.EventHeader.ProcessId;
  ne.tid = record.EventHeader.ThreadId;
  ne.eventId = static_cast<int>(record.EventHeader.EventDescriptor.Id);
  ne.fields["SourcePid"] = static_cast<uint32_t>(ne.pid);

  try {
    krabs::schema schema(record, ctx.schema_locator);

    try {
      ne.provider = Utils::narrow_utf8(schema.provider_name());
    } catch (...) {
      ne.provider = "<unknown_provider>";
    }

    try {
      const auto evW = Utils::composeEvent(schema);
      ne.fields["event"] = Utils::narrow_utf8(evW);
    } catch (...) {
    }

    try {
      ne.fields["task_name"] = Utils::narrow_utf8(schema.task_name());
    } catch (...) {
    }

    SafeKrabsParserSession parser(schema);

    auto tryU32 = [&](const wchar_t *name) -> std::optional<uint32_t> {
      return parser.tryParse<uint32_t>(name);
    };

    auto tryU64 = [&](const wchar_t *name) -> std::optional<uint64_t> {
      return parser.tryParse<uint64_t>(name);
    };
    auto tryWStr = [&](const wchar_t *name) -> std::optional<std::wstring> {
      return parser.tryParse<std::wstring>(name);
    };

    auto setFirstU32 = [&](std::string_view dst, std::initializer_list<const wchar_t *> aliases) {
      for (const auto *a : aliases) {
        if (auto v = tryU32(a)) {
          ne.fields[std::string(dst)] = *v;
          return true;
        }
        if (parser.isPoisoned()) {
          return false;
        }
      }
      return false;
    };
    auto setFirstU64 = [&](std::string_view dst, std::initializer_list<const wchar_t *> aliases) {
      for (const auto *a : aliases) {
        if (auto v = tryU64(a)) {
          ne.fields[std::string(dst)] = *v;
          return true;
        }
        if (parser.isPoisoned()) {
          return false;
        }
      }
      return false;
    };
    auto setFirstStr = [&](std::string_view dst, std::initializer_list<const wchar_t *> aliases) {
      for (const auto *a : aliases) {
        if (auto v = tryWStr(a)) {
          ne.fields[std::string(dst)] = Utils::narrow_utf8(*v);
          return true;
        }
        if (parser.isPoisoned()) {
          return false;
        }
      }
      return false;
    };

    const bool hasSourcePid = setFirstU32("SourcePid", {L"SourcePid", L"SourceProcessId"});
    (void)hasSourcePid;
    if (!parser.isPoisoned()) {
      setFirstU32("TargetPid", {L"TargetPid", L"TargetProcessId", L"ProcessId"});
    }
    if (!parser.isPoisoned()) {
      // Keep TargetThreatId for compatibility with malformed legacy event payloads.
      setFirstU32("TargetTid", {L"TargetTid", L"TargetThreadId", L"TargetThreatId", L"TThreadId"});
    }
    if (!parser.isPoisoned()) {
      setFirstU32("ProcessId", {L"ProcessId"});
    }
    if (!parser.isPoisoned()) {
      setFirstU32("TThreadId", {L"TThreadId"});
    }
    if (!parser.isPoisoned()) {
      if (!setFirstU64("DesiredAccess", {L"DesiredAccess", L"GrantedAccess"})) {
        setFirstU32("DesiredAccess", {L"DesiredAccess", L"GrantedAccess"});
      }
    }
    if (!parser.isPoisoned()) {
      if (!setFirstU64("GrantedAccess", {L"GrantedAccess", L"DesiredAccess"})) {
        setFirstU32("GrantedAccess", {L"GrantedAccess", L"DesiredAccess"});
      }
    }
    if (!parser.isPoisoned()) {
      setFirstU32("ReturnCode", {L"ReturnCode", L"ReturnValue"});
    }
    if (!parser.isPoisoned()) {
      setFirstStr("Image", {L"Image", L"ImagePath", L"ProcessPath", L"ProcessName", L"ImageFileName", L"NewProcessName"});
    }
    if (!parser.isPoisoned()) {
      setFirstStr("SourceImage", {L"SourceImage", L"CallerProcessName", L"SourceProcessName"});
    }
    if (!parser.isPoisoned()) {
      setFirstStr("TargetImage", {L"TargetImage", L"TargetProcessName", L"TargetProcessPath"});
    }
    if (!parser.isPoisoned()) {
      setFirstStr("ObjectName", {L"ObjectName", L"TargetObject", L"RegName", L"KeyName", L"Path"});
    }
    if (!parser.isPoisoned()) {
      setFirstStr("TaskName", {L"TaskName"});
    }
    if (!parser.isPoisoned()) {
      setFirstStr("ServiceName", {L"ServiceName"});
    }
    if (!parser.isPoisoned()) {
      setFirstStr("EventType", {L"EventType"});
    }

    if (!parser.isPoisoned()) {
      if (auto v = tryU64(L"TargetProcessStartKey")) {
        ne.fields["TargetProcessStartKey"] = *v;
      }
    }
    if (!parser.isPoisoned()) {
      if (auto v = tryU64(L"TargetProcessCreationTime")) {
        ne.fields["TargetProcessCreationTime"] = *v;
      }
    }
  } catch (...) {
    ne.provider = "<no_schema>";
  }

  if (!ne.fields.contains("SourcePid")) {
    ne.fields["SourcePid"] = static_cast<uint32_t>(ne.pid);
  }

  m_threadAnalysis.onEvent(ne);
}

void ProcessMonitor::_onKernelEvent(const EVENT_RECORD &record,
                                    const krabs::trace_context &ctx) {
  _refreshTargetPidsIfNeeded(false, true);
  if (!_pidAllowed(record, ctx)) {
    return;
  }

  logEvent(record, ctx);
}

void ProcessMonitor::_onUserEvent(const EVENT_RECORD &record,
                                  const krabs::trace_context &ctx) {
  if (!_pidAllowed(record, ctx)) {
    return;
  }

  logEvent(record, ctx);
}

std::set<DWORD> ProcessMonitor::findPidsByName(const std::wstring &exeName) const {
  std::set<DWORD> pids;
  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, ProcessMonitorConstants::ALL_PROCESSES_SNAPSHOT);
  if (snap == INVALID_HANDLE_VALUE) {
    return pids;
  }

  PROCESSENTRY32W pe{};
  pe.dwSize = sizeof(pe);

  if (Process32FirstW(snap, &pe)) {
    do {
      if (_wcsicmp(pe.szExeFile, exeName.c_str()) == 0) {
        pids.insert(pe.th32ProcessID);
      }
    } while (Process32NextW(snap, &pe));
  }
  CloseHandle(snap);
  return pids;
}

void ProcessMonitor::start() {
  m_threads.kernel = std::jthread([this] { _enableKernelProviders(); });
  m_threads.user = std::jthread([this] { _enableUserProviders(); });
  m_threads.sysmon = std::jthread([this](std::stop_token stopToken) { _enableSysmonChannel(stopToken); });
}

void ProcessMonitor::stop() {
  m_kernel.stop();
  m_user.stop();
  m_threads.sysmon.request_stop();
  if (m_threads.kernel.joinable()) {
    m_threads.kernel.join();
  }

  if (m_threads.user.joinable()) {
    m_threads.user.join();
  }

  if (m_threads.sysmon.joinable()) {
    m_threads.sysmon.join();
  }
}

static bool s_joinWithDeadline(std::jthread &t, const Deadline &deadline, const char *tag) {
  if (!t.joinable()) {
    return true;
  }

  const auto rem = deadline.remaining_ms();
  const DWORD waitMs = static_cast<DWORD>(std::clamp<long long>(rem.count(), ProcessMonitorConstants::MIN_WAIT_MS, ProcessMonitorConstants::MAX_WAIT_MS));
  const HANDLE h = reinterpret_cast<HANDLE>(t.native_handle());
  const DWORD res = WaitForSingleObject(h, waitMs);
  if (res == WAIT_OBJECT_0) {
    t.join();
    return true;
  }

  std::string msg = std::string("ProcessMonitor: thread '") + (tag ? tag : "unknown") + "' join timed out; detaching\n";
  OutputDebugStringA(msg.c_str());
  t.detach();
  return false;
}

bool ProcessMonitor::waitForTarget(const Deadline &deadline,
                                   std::chrono::milliseconds pollInterval) {
  if (!m_targetExeName.has_value()) {
    return true; // explicit PID list supplied
  }

  while (!deadline.expired()) {
    _refreshTargetPidsIfNeeded(true, true);
    if (!_targetPidsSnapshot().empty()) {
      return true;
    }

    const auto remaining = deadline.remaining_ms();
    const auto sleepFor = (pollInterval < remaining) ? pollInterval : remaining;
    if (sleepFor.count() > 0) {
      std::this_thread::sleep_for(sleepFor);
    }
  }

  OutputDebugStringA("ProcessMonitor: target process not found before deadline\n");
  return false;
}

bool ProcessMonitor::stopWithDeadline(const Deadline &deadline) {
  bool ok = true;
  ok &= m_kernel.stopWithDeadline(deadline);
  ok &= m_user.stopWithDeadline(deadline);
  m_threads.sysmon.request_stop();
  ok &= s_joinWithDeadline(m_threads.kernel, deadline, "kernel_thread");
  ok &= s_joinWithDeadline(m_threads.user, deadline, "user_thread");
  ok &= s_joinWithDeadline(m_threads.sysmon, deadline, "sysmon_thread");
  _emitProviderSummary();
  return ok;
}

void ProcessMonitor::_enableKernelProviders() {
  m_kernel.addDefaultKernelProviders();
  m_kernel.start([this](const EVENT_RECORD &rec, const krabs::trace_context &ctx) {
    _onKernelEvent(rec, ctx);
  });
}

void ProcessMonitor::_enableUserProviders() {
  m_user.addAnalystProviders(TRACE_LEVEL_INFORMATION,
                             ProcessMonitorConstants::DEFAULT_ANY_MASK,
                             ProcessMonitorConstants::DEFAULT_ALL_MASK);
  m_user.start([this](const EVENT_RECORD &rec, const krabs::trace_context &ctx) {
    _onUserEvent(rec, ctx);
  });
}

void ProcessMonitor::_enableSysmonChannel(std::stop_token stopToken) {
  const auto latestRecordId = s_getLatestSysmonRecordId();
  if (!latestRecordId.has_value()) {
    std::wcout << ProcessMonitorConstants::SYSMON_DISABLED_CONSOLE_MSG << std::endl;
    OutputDebugStringA(ProcessMonitorConstants::SYSMON_UNAVAILABLE_MSG);
    return;
  }

  std::wcout << ProcessMonitorConstants::SYSMON_ENABLED_CONSOLE_MSG << std::endl;
  std::uint64_t lastRecordId = *latestRecordId;
  bool loggedQueryFailure = false;

  while (!stopToken.stop_requested()) {
    const std::wstring queryText = L"*[System[(EventRecordID > " + std::to_wstring(lastRecordId) + L")]]";
    EVT_HANDLE query = EvtQuery(nullptr,
                                ProcessMonitorConstants::SYSMON_CHANNEL_NAME.data(),
                                queryText.c_str(),
                                EvtQueryChannelPath);
    if (!query) {
      if (!loggedQueryFailure) {
        const DWORD err = GetLastError();
        std::ostringstream oss;
        oss << "ProcessMonitor: EvtQuery(Sysmon) failed, err=" << err << "\n";
        OutputDebugStringA(oss.str().c_str());
        loggedQueryFailure = true;
      }
      std::this_thread::sleep_for(ProcessMonitorConstants::SYSMON_QUERY_POLL_INTERVAL);
      continue;
    }

    loggedQueryFailure = false;
    EVT_HANDLE events[16]{};
    DWORD returned = 0;
    while (!stopToken.stop_requested() &&
           EvtNext(query, static_cast<DWORD>(std::size(events)), events, 0, 0, &returned)) {
      for (DWORD i = 0; i < returned; ++i) {
        const EVT_HANDLE eventHandle = events[i];
        if (!eventHandle) {
          continue;
        }

        const auto xml = s_renderEventXml(eventHandle);
        if (xml.has_value()) {
          const auto parsed = s_parseSysmonEventXml(*xml);
          if (parsed.has_value()) {
            lastRecordId = std::max(lastRecordId, parsed->recordId);

            nlohmann::json eventJson;
            eventJson["ts"] = parsed->timeCreated.empty() ? Utils::iso8601FromTimePoint(std::chrono::system_clock::now()) : parsed->timeCreated;
            eventJson["host"] = parsed->computer.empty() ? Utils::getHostName() : parsed->computer;
            eventJson["EventRecordId"] = parsed->recordId;
            eventJson["Channel"] = parsed->channel;
            eventJson["Level"] = parsed->level;
            eventJson["Task"] = parsed->task;
            eventJson["Opcode"] = parsed->opcode;
            eventJson["Keywords"] = parsed->keywords;
            eventJson["event_id"] = parsed->eventId;
            eventJson["pid"] = parsed->logicalPid;
            eventJson["tid"] = parsed->logicalTid;
            eventJson["provider"] = parsed->provider;
            eventJson["task_name"] = parsed->taskName;
            eventJson["event"] = parsed->eventName;
            eventJson["props"] = parsed->props;

            _recordProviderCount(ProcessMonitorConstants::SYSMON_PROVIDER_GUID);
            const auto prev = m_sysmonDebugLogged.fetch_add(1, std::memory_order_relaxed);
            if (prev < ProcessMonitorConstants::MAX_SYSMON_DEBUG_LOGS) {
              const std::string msg = std::string("Sysmon channel event: id=") + std::to_string(parsed->eventId) + "\n";
              OutputDebugStringA(msg.c_str());
            }

            m_writer->writeEventJson(std::move(eventJson));
            {
              std::scoped_lock lk(m_analysisMtx);
              m_threadAnalysis.onEvent(parsed->normalized);
            }
          }
        }

        EvtClose(eventHandle);
      }
      returned = 0;
    }

    const DWORD err = GetLastError();
    if (err != ERROR_NO_MORE_ITEMS) {
      std::ostringstream oss;
      oss << "ProcessMonitor: EvtNext(Sysmon) failed, err=" << err << "\n";
      OutputDebugStringA(oss.str().c_str());
    }

    EvtClose(query);
    if (!stopToken.stop_requested()) {
      std::this_thread::sleep_for(ProcessMonitorConstants::SYSMON_QUERY_POLL_INTERVAL);
    }
  }
}

void ProcessMonitor::logEvent(const EVENT_RECORD &record,
                              const krabs::trace_context &ctx) {
  _recordProviderCount(record.EventHeader.ProviderId);

  if (InlineIsEqualGUID(record.EventHeader.ProviderId, ProcessMonitorConstants::SYSMON_PROVIDER_GUID)) {
    const auto prev = m_sysmonDebugLogged.fetch_add(1, std::memory_order_relaxed);
    if (prev < ProcessMonitorConstants::MAX_SYSMON_DEBUG_LOGS) {
      const auto providerStr = s_guidToString(record.EventHeader.ProviderId);
      const auto evtId = static_cast<unsigned>(record.EventHeader.EventDescriptor.Id);
      const std::string msg = std::string("Sysmon event: provider=") + providerStr + " id=" + std::to_string(evtId) + "\n";
      OutputDebugStringA(msg.c_str());
    }
  }

  (*m_writer)(record, ctx);
  _analyzeRecord(record, ctx);
}
