#pragma once

#include <chrono>
#include <string_view>
#include <windows.h>

namespace SelfTestLiveConstants {
inline constexpr UCHAR TRACE_LEVEL = TRACE_LEVEL_INFORMATION;
inline constexpr ULONGLONG ANY_MASK = 0;
inline constexpr ULONGLONG ALL_MASK = 0;
inline constexpr auto CAPTURE_DURATION = std::chrono::seconds(2);
inline constexpr auto STOP_GRACE = std::chrono::seconds(3);
inline constexpr std::wstring_view SESSION_NAME = L"NTUserLoggerLiveSelfTest";
} // namespace SelfTestLiveConstants
