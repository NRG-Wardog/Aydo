#pragma once

#include <chrono>
#include <cstdlib>
#include <string_view>

namespace MainConstants {
inline constexpr int SELF_TEST_ARG_COUNT = 2;
inline constexpr int EXECUTABLE_ARG_INDEX = 1;
inline constexpr int OUTPUT_PATH_ARG_INDEX = 2;
inline constexpr int TRACE_DURATION_ARG_INDEX = 3;
inline constexpr int MIN_RUN_ARG_COUNT = 3;
inline constexpr int MAX_RUN_ARG_COUNT = 4;
inline constexpr int MIN_TRACE_DURATION_SECONDS = 1;
inline constexpr int HARD_STOP_EXIT_CODE = EXIT_FAILURE;
inline constexpr auto TARGET_POLL_INTERVAL = std::chrono::milliseconds(250);
inline constexpr auto STOP_GRACE_PERIOD = std::chrono::seconds(5);

inline constexpr std::wstring_view SELF_TEST_FLAG = L"--self-test";
inline constexpr std::wstring_view SELF_TEST_LIVE_FLAG = L"--self-test-live";
inline constexpr std::wstring_view KERNEL_SESSION_NAME = L"NTKernelLogger";
inline constexpr std::wstring_view USER_SESSION_NAME = L"NTUserLogger";
} // namespace MainConstants
