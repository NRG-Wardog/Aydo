#pragma once

#include <ntifs.h>

#define CHECK_NT_RETURN(status, fmt, ...) \
  do {                                    \
    if (!NT_SUCCESS(status)) {            \
      LOG_ERROR(fmt, ##__VA_ARGS__);        \
      return status;                      \
    }                                     \
  } while (0)

#define CHECK_NT_RETURN_CLEANUP(status, cleanup, fmt, ...) \
  do {                                                     \
    if (!NT_SUCCESS(status)) {                             \
      LOG_ERROR(fmt, ##__VA_ARGS__);                         \
      cleanup;                                             \
      return status;                                       \
    }                                                      \
  } while (0)

#define CHECK_NT_RETURN_FALSE(status, fmt, ...) \
  do {                                          \
    if (!NT_SUCCESS(status)) {                  \
      LOG_ERROR(fmt, ##__VA_ARGS__);              \
      return false;                             \
    }                                           \
  } while (0)

#define CHECK_NT_RETURN_FALSE_CLEANUP(status, cleanup, fmt, ...) \
  do {                                                           \
    if (!NT_SUCCESS(status)) {                                   \
      LOG_ERROR(fmt, ##__VA_ARGS__);                               \
      cleanup;                                                   \
      return false;                                              \
    }                                                            \
  } while (0)

extern "C" NTSTATUS NTAPI ZwQueryInformationProcess(
    _In_ HANDLE ProcessHandle,
    _In_ PROCESSINFOCLASS ProcessInformationClass,
    _Out_ PVOID ProcessInformation,
    _In_ ULONG ProcessInformationLength,
    _Out_opt_ PULONG ReturnLength);

#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE 0x0001
#endif

#ifndef PROCESS_QUERY_INFORMATION
#define PROCESS_QUERY_INFORMATION 0x0400
#endif

// Basic list of protected processes (shouldn't be killed)
static const ULONG PROTECTED_PROCESSES[] = {
    0, // NtOSKRNL
    4, // System
};

namespace Utils {
NTSTATUS killProcessByPID(ULONG pid);
bool isProcessKillable(ULONG pid);
NTSTATUS initializeProcessNotifications();
VOID cleanupProcessNotifications();
PVOID dequeueProcessNotification();
VOID enqueueProcessNotification(PVOID notification);
NTSTATUS suspendProcess(HANDLE processId);
NTSTATUS resumeProcess(ULONG pid);
BOOLEAN isValidUnicodeString(PCUNICODE_STRING unicodeString);
} // namespace Utils