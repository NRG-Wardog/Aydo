#pragma once

#include <chrono>
#include <cstdint>
#include <guiddef.h>
#include <string_view>

namespace ProcessMonitorConstants {
inline constexpr std::uint32_t INVALID_PID = 0;
inline constexpr std::uint32_t ALL_PROCESSES_SNAPSHOT = 0;
inline constexpr std::uint64_t DEFAULT_ANY_MASK = 0;
inline constexpr std::uint64_t DEFAULT_ALL_MASK = 0;
inline constexpr long long MIN_WAIT_MS = 0;
inline constexpr long long MAX_WAIT_MS = 0x7fffffff;
inline constexpr std::wstring_view SYSMON_PROVIDER_NAME = L"Microsoft-Windows-Sysmon";
inline constexpr std::wstring_view SYSMON_CHANNEL_NAME = L"Microsoft-Windows-Sysmon/Operational";
inline constexpr GUID SYSMON_PROVIDER_GUID = {
    0x5770385f, 0xc22a, 0x43e0, {0xbf, 0x4c, 0x06, 0xf5, 0x69, 0x8f, 0xfb, 0xd9}};
inline constexpr std::uint64_t SYSMON_KEYWORD = 0x8000000000000000ULL;
inline constexpr std::wstring_view PID_SEPARATOR = L", ";
inline constexpr std::wstring_view PROCESS_LIST_PREFIX = L"process : ";
inline constexpr std::wstring_view PROCESS_NONE_VALUE = L"none";
inline constexpr std::wstring_view PROCESS_STARTED_SUFFIX = L"> is now working";
inline constexpr std::wstring_view PROCESS_STOPPED_SUFFIX = L"> got stop";
inline constexpr std::wstring_view SYSMON_ENABLED_CONSOLE_MSG = L"Sysmon channel: enabled";
inline constexpr std::wstring_view SYSMON_DISABLED_CONSOLE_MSG = L"Sysmon channel: unavailable";
inline constexpr auto TARGET_PID_REFRESH_INTERVAL = std::chrono::milliseconds(1000);
inline constexpr auto SYSMON_QUERY_POLL_INTERVAL = std::chrono::milliseconds(250);
inline constexpr const char *SYSMON_UNAVAILABLE_MSG = "ProcessMonitor: Sysmon channel unavailable; continuing without Sysmon\n";
inline constexpr std::uint32_t MAX_SYSMON_DEBUG_LOGS = 10;
} // namespace ProcessMonitorConstants
