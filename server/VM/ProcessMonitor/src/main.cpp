#include "pch.h"

#include <iostream>
#include <memory>
#include <condition_variable>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <windows.h>

#include "Constants.hpp"
#include "Deadline.hpp"
#include "MainConstants.hpp"
#include "ProcessMonitor.hpp"
#include "SelfTest.hpp"

int wmain(int argc, wchar_t *argv[]) {
  if (argc == MainConstants::SELF_TEST_ARG_COUNT && _wcsicmp(argv[MainConstants::EXECUTABLE_ARG_INDEX], MainConstants::SELF_TEST_FLAG.data()) == 0) {
    return RunProcessMonitorSelfTest();
  }
  if (argc == MainConstants::SELF_TEST_ARG_COUNT && _wcsicmp(argv[MainConstants::EXECUTABLE_ARG_INDEX], MainConstants::SELF_TEST_LIVE_FLAG.data()) == 0) {
    return RunProcessMonitorLiveSelfTest();
  }

  if (argc < MainConstants::MIN_RUN_ARG_COUNT || argc > MainConstants::MAX_RUN_ARG_COUNT) {
    std::wcerr << L"Usage: " << argv[0] << L" <exefile> <logFile> [TraceTime]" << std::endl;
    std::wcerr << L"       " << argv[0] << L" --self-test" << std::endl;
    std::wcerr << L"       " << argv[0] << L" --self-test-live" << std::endl;

    return EXIT_FAILURE;
  }

  const std::wstring targetExe = argv[MainConstants::EXECUTABLE_ARG_INDEX];
  const std::wstring outputPath = argv[MainConstants::OUTPUT_PATH_ARG_INDEX];

  const int traceDurationSeconds =
      (argc == MainConstants::MAX_RUN_ARG_COUNT) ? _wtoi(argv[MainConstants::TRACE_DURATION_ARG_INDEX]) : Constants::DEFAULT_TRACE_DURATION_SECONDS;
  if (traceDurationSeconds < MainConstants::MIN_TRACE_DURATION_SECONDS) {
    std::wcerr << L"TraceTime must be >= " << MainConstants::MIN_TRACE_DURATION_SECONDS << L" seconds" << std::endl;
    return EXIT_FAILURE;
  }

  std::mutex watchdogMtx;
  std::condition_variable watchdogCv;
  bool watchdogCancelled = false;
  std::thread watchdog;
  auto cancelWatchdog = [&]() {
    if (!watchdog.joinable()) {
      return;
    }
    {
      std::lock_guard lk(watchdogMtx);
      watchdogCancelled = true;
    }
    watchdogCv.notify_one();
    watchdog.join();
  };

  try {
    std::wcout << L"Starting ProcessMonitor"
               << L": target='" << targetExe
               << L"', output='" << outputPath
               << L"', trace_seconds=" << traceDurationSeconds << std::endl;

    // Hard watchdog: enforce process lifetime upper bound regardless of stop/join behavior.
    watchdog = std::thread([&watchdogMtx, &watchdogCv, &watchdogCancelled, hardStopAfter = std::chrono::seconds(traceDurationSeconds)] {
      std::unique_lock lk(watchdogMtx);
      if (!watchdogCv.wait_for(lk, hardStopAfter, [&watchdogCancelled] { return watchdogCancelled; })) {
        OutputDebugStringA("ProcessMonitor: hard stop reached; terminating process\n");
        TerminateProcess(GetCurrentProcess(), MainConstants::HARD_STOP_EXIT_CODE);
      }
    });

    const auto now = std::chrono::steady_clock::now();
    Deadline deadline(now + std::chrono::seconds(traceDurationSeconds));
    const Deadline stopDeadline(deadline.time_point() + MainConstants::STOP_GRACE_PERIOD); // grace

    auto pm = std::make_unique<ProcessMonitor>(
        targetExe,
        std::wstring(MainConstants::KERNEL_SESSION_NAME),
        std::wstring(MainConstants::USER_SESSION_NAME),
        outputPath);

    if (!pm->waitForTarget(deadline, MainConstants::TARGET_POLL_INTERVAL)) {
      std::wcerr << L"Target process '" << targetExe << L"' not found before deadline" << std::endl;
      cancelWatchdog();
      return EXIT_FAILURE;
    }
    // Start monitor
    pm->start();

    if (const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline.time_point() - std::chrono::steady_clock::now()); remaining.count() > 0) {
      std::this_thread::sleep_for(remaining);
    }

    if (!pm->stopWithDeadline(stopDeadline)) {
      std::wcerr << L"ProcessMonitor stop exceeded deadline; some events may be lost" << std::endl;
    }
    cancelWatchdog();
  } catch (...) {
    cancelWatchdog();
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}
