#include "../Utils.hpp"
#include "Constants.hpp"
#include "UtilsConstants.hpp"

std::wstring Utils::trimWs(std::wstring s) {
  auto is_space = [](wchar_t c) { return c == L' ' || c == L'\t' || c == L'\n' || c == L'\r'; };
  size_t b = 0;
  size_t e = s.size();
  while (b < e && is_space(s[b])) {
    ++b;
  }

  while (e > b && is_space(s[e - 1])) {
    --e;
  }

  return s.substr(b, e - b);
}

std::wstring Utils::toLower(std::wstring s) {
  for (auto &c : s) {
    c = (wchar_t)towlower(c);
  }

  return s;
}

std::string Utils::toLower(std::string s) {
  for (auto &c : s) {
    c = (char)towlower(c);
  }

  return s;
}

std::wstring Utils::composeEvent(const krabs::schema &s) {
  std::wstring ev;
  try {
    ev = s.event_name();
  } catch (...) {
  }
  ev = trimWs(ev);
  if (!ev.empty()) {
    return ev;
  }

  std::wstring task;
  std::wstring op;
  try {
    task = s.task_name();
  } catch (...) {
  }
  try {
    op = s.opcode_name();
  } catch (...) {
  }
  task = trimWs(task);
  op = trimWs(op);

  if (!task.empty() || !op.empty()) {
    std::wstring out = task;
    if (!op.empty()) {
      if (!out.empty()) {
        out += L"/";
      }

      out += op;
    }
    return out.empty() ? L"#" + std::to_wstring(s.event_opcode()) : out;
  }
  return L"#" + std::to_wstring(s.event_opcode());
}

std::string Utils::inferCategory(const std::wstring &providerW, const std::wstring &taskW) {
  auto p = toLower(providerW);
  auto t = toLower(taskW);
  if (p.contains(L"dotnetruntime")) {
    return ".net";
  }

  if (p.contains(L"dns-client")) {
    return "dns";
  }

  if (p.contains(L"winhttp") ||
      p.contains(L"http")) {
    return "http";
  }

  if (p.contains(L"wmi-activity")) {
    return "wmi";
  }

  if (p.contains(L"powershell")) {
    return "ps";
  }

  if (p.contains(L"tcpip")) {
    return "net";
  }

  if (p.contains(L"kernel")) {
    if (t.contains(L"thread")) {
      return "thread";
    }

    if (t.contains(L"process")) {
      return "process";
    }

    if (t.contains(L"file")) {
      return "file";
    }

    if (t.contains(L"registry")) {
      return "reg";
    }

    return "kernel";
  }
  if (t.contains(L"registry")) {
    return "reg";
  }

  if (t.contains(L"file")) {
    return "file";
  }

  if (t.contains(L"network") ||
      t.contains(L"tcp")) {
    return "net";
  }

  return "other";
}

void Utils::setIfFound(nlohmann::json &dst, const char *key, const nlohmann::json &src, std::initializer_list<const char *> names) {
  for (auto n : names) {
    auto it = src.find(n);
    if (it != src.end() && !it->is_null()) {
      dst[key] = *it;

      return;
    }
  }
}

std::wstring_view Utils::trim(std::wstring_view x) {
  auto is_space = [](wchar_t ch) {
    return std::iswspace(static_cast<wint_t>(ch)) != 0;
  };

  // first non-space
  auto first = std::ranges::find_if_not(x, is_space);
  if (first == x.end()) {
    return {};
  }

  // last non-space
  auto r = x | std::views::reverse;
  auto rpos = std::ranges::find_if_not(r, is_space); // iterator into the reversed view
  auto last = rpos.base();                           // convert back to forward iterator

  return {std::to_address(first), static_cast<size_t>(last - first)};
}

nlohmann::json Utils::normalizeProto(const nlohmann::json &props) {
  auto it = props.find("Protocol");
  if (it != props.end()) {
    if (it->is_number_integer()) {
      int v = *it;
      if (v == Constants::IP_PROTOCOL_TCP) {
        return "TCP";
      }

      if (v == Constants::IP_PROTOCOL_UDP) {
        return "UDP";
      }

      return v;
    }

    return *it;
  }
  it = props.find("protocol");
  if (it != props.end()) {
    return *it;
  }

  return nlohmann::json();
}

nlohmann::json Utils::extractNet(const nlohmann::json &props) {
  nlohmann::json net;
  setIfFound(net, "dst", props, {"daddr", "DestAddress", "DestIp", "RemoteIP", "DestinationIp", "dstIp"});
  setIfFound(net, "dport", props, {"dport", "DestPort", "RemotePort", "DestinationPort", "dstPort"});
  if (auto proto = normalizeProto(props); !proto.is_null()) {
    net["proto"] = proto;
  }

  return net;
}

std::string Utils::ntStatusToText(const nlohmann::json &v) {
  if (v.is_number_integer()) {
    auto code = (unsigned long)v.get<long long>();
    if (code == 0) {
      return "SUCCESS";
    }

    std::ostringstream oss;
    oss << "0x" << std::hex << code;
    return oss.str();
  }
  if (v.is_string()) {
    return v.get<std::string>();
  }

  return "UNKNOWN";
}

nlohmann::json Utils::extractDns(const nlohmann::json &props) {
  nlohmann::json dns;
  setIfFound(dns, "qname", props, {"QueryName", "Name", "Query", "DomainName"});
  setIfFound(dns, "qtype", props, {"QueryType", "Type"});
  setIfFound(dns, "rcode", props, {"QueryStatus", "Status", "ResponseCode", "RCode"});
  return dns;
}

nlohmann::json Utils::extractFile(const nlohmann::json &props, const std::wstring &task, const std::wstring &opname) {
  nlohmann::json f;
  setIfFound(f, "path", props, {"FileName", "FilePath", "ObjectName", "ImagePath", "Path"});
  setIfFound(f, "op", props, {"Operation", "IrpOp"});

  if (!f.contains("op")) {
    std::wstring op = trimWs(opname);
    std::wstring tk = trimWs(task);
    std::wstring combo = tk;
    if (!op.empty()) {
      if (!combo.empty()) {
        combo += L"/";
      }
      combo += op;
    }
    if (!combo.empty()) {
      f["op"] = narrow_utf8(combo);
    }
  }

  if (auto it = props.find("Status"); it != props.end()) {
    f["status"] = ntStatusToText(*it);
  } else if (auto it2 = props.find("NtStatus"); it2 != props.end()) {
    f["status"] = ntStatusToText(*it2);
  } else if (auto it3 = props.find("ReturnValue"); it3 != props.end()) {
    f["status"] = ntStatusToText(*it3);
  }
  return f;
}

int Utils::resolveBitness(HANDLE h) {
  HMODULE k32 = ::GetModuleHandleW(L"kernel32.dll");
  if (auto pIsWow64Process2 = reinterpret_cast<IsWow64Process2_t>(
          GetProcAddress(k32, "IsWow64Process2"));
      pIsWow64Process2) {
    USHORT processMachine = 0;
    USHORT nativeMachine = 0;
    if (pIsWow64Process2(h, &processMachine, &nativeMachine)) {
      bool isNative64 = (nativeMachine == IMAGE_FILE_MACHINE_AMD64 ||
                         nativeMachine == IMAGE_FILE_MACHINE_ARM64);
      bool isWow = (processMachine != IMAGE_FILE_MACHINE_UNKNOWN);
      if (isNative64 && !isWow) {
        return Constants::BITNESS_64;
      }

      if (isNative64 && isWow) {
        return Constants::BITNESS_32;
      }
    }
  } else {
    BOOL wow = FALSE;
    if (IsWow64Process(h, &wow)) {
      SYSTEM_INFO si{};
      GetNativeSystemInfo(&si);
      bool os64 = (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ||
                   si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64);
      if (os64) {
        return wow ? Constants::BITNESS_32 : Constants::BITNESS_64;
      }
    }
  }
  return Constants::BITNESS_64; // assumption
}

std::string Utils::narrow_utf8(const std::wstring &w) {
  if (w.empty()) {
    return {};
  }

  int n = ::WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
  std::string s(n, '\0');
  ::WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), s.data(), n, nullptr, nullptr);
  return s;
}

std::wstring Utils::widenUtf8(const std::string &s) {
  if (s.empty()) {
    return L"";
  }

  int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
  std::wstring w(n, 0);
  MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), w.data(), n);
  return w;
}

nlohmann::json Utils::bestEffortProcFromPid(DWORD pid) {
  nlohmann::json p;
  if (pid == 0 || pid == Constants::INVALID_PID) {
    return p;
  }

  if (HANDLE h = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid); h) {
    wchar_t buf[MAX_PATH];
    if (DWORD sz = MAX_PATH; QueryFullProcessImageNameW(h, 0, buf, &sz)) {
      std::wstring wpath(buf, sz);
      p["path"] = narrow_utf8(wpath);
      auto pos = wpath.find_last_of(L"\\/");
      p["name"] = narrow_utf8(pos == std::wstring::npos ? wpath : wpath.substr(pos + 1));
    }
    p["bitness"] = resolveBitness(h);
    ::CloseHandle(h);
  }
  return p;
}

nlohmann::json Utils::normUintOrNull(ULONG v) {
  return (v == Constants::INVALID_PID) ? nlohmann::json(nullptr) : nlohmann::json(v);
}

unsigned long long Utils::ts100nsFromLargeInteger(const LARGE_INTEGER &ts) {
  ULARGE_INTEGER u;
  u.LowPart = ts.LowPart;
  u.HighPart = ts.HighPart;
  return u.QuadPart;
}

std::string Utils::getHostName() {
  wchar_t buf[Constants::HOST_NAME_BUFFER_CHARS]{};
  DWORD len = (DWORD)std::size(buf);
  if (GetComputerNameExW(ComputerNamePhysicalDnsHostname, buf, &len)) {
    return Utils::narrow_utf8(std::wstring(buf, len));
  }

  len = (DWORD)std::size(buf);
  if (GetComputerNameW(buf, &len)) {
    return Utils::narrow_utf8(std::wstring(buf, len));
  }

  return {};
}

std::string Utils::iso8601FromLargeIntegerTimestamp(const LARGE_INTEGER &ts) {
  ULARGE_INTEGER uli{};
  uli.QuadPart = static_cast<ULONGLONG>(ts.QuadPart);
  FILETIME ft{.dwLowDateTime = ts.LowPart, .dwHighDateTime = uli.HighPart};
  SYSTEMTIME st_utc{};

  if (!FileTimeToSystemTime(&ft, &st_utc)) {
    return {};
  }
  std::ostringstream oss;
  oss << std::setfill('0')
      << std::setw(UtilsConstants::ISO8601_YEAR_WIDTH) << st_utc.wYear << "-"
      << std::setw(UtilsConstants::ISO8601_DATETIME_FIELD_WIDTH) << st_utc.wMonth << "-"
      << std::setw(UtilsConstants::ISO8601_DATETIME_FIELD_WIDTH) << st_utc.wDay << "T"
      << std::setw(UtilsConstants::ISO8601_DATETIME_FIELD_WIDTH) << st_utc.wHour << ":"
      << std::setw(UtilsConstants::ISO8601_DATETIME_FIELD_WIDTH) << st_utc.wMinute << ":"
      << std::setw(UtilsConstants::ISO8601_DATETIME_FIELD_WIDTH) << st_utc.wSecond << "."
      << std::setw(UtilsConstants::ISO8601_MILLISECONDS_WIDTH) << st_utc.wMilliseconds << "Z";

  return oss.str();
}

std::string Utils::iso8601FromTimePoint(std::chrono::system_clock::time_point tp) {
  const auto t = std::chrono::system_clock::to_time_t(tp);

  std::tm tm{};
  gmtime_s(&tm, &t);

  const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(tp.time_since_epoch()) % Constants::MILLISECONDS_PER_SECOND;

  std::ostringstream oss;
  oss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%S")
      << '.' << std::setw(UtilsConstants::ISO8601_MILLISECONDS_WIDTH) << std::setfill('0') << ms.count()
      << 'Z';
  return oss.str();
}

std::string Utils::guidToString(const GUID &g) {
  wchar_t buf[Constants::GUID_STRING_BUFFER_CHARS];
  if (int n = ::StringFromGUID2(g, buf, Constants::GUID_STRING_BUFFER_CHARS); n <= 0) {
    return {};
  }

  return Utils::narrow_utf8(buf);
}

// Try get a non-null value from a JSON object by key
const nlohmann::json *Utils::getIfPresent(const nlohmann::json &obj,
                                          const std::string &key) {
  if (!obj.is_object()) {
    return nullptr;
  }
  auto it = obj.find(key);
  if (it == obj.end() || it->is_null()) {
    return nullptr;
  }
  return std::addressof(*it);
}

