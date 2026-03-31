#include "Utils.hpp"

#include "Hooks.hpp"
#include "Logger.hpp"
#include "Types.hpp"

extern "C" {
NTSTATUS PsSuspendProcess(PEPROCESS Process);
NTSTATUS PsResumeProcess(PEPROCESS Process);
}

static LIST_ENTRY g_ProcessNotificationQueue;
static KSPIN_LOCK g_QueueLock;
static BOOLEAN g_IsInitialized = FALSE;

// Kills a process by its PID
//  ** Does not perform any checks for whether the process shouldn't be killed **
NTSTATUS Utils::killProcessByPID(ULONG pid) {
  LOG_INFO("Killing process by PID: %lu", pid);

  PEPROCESS process;
  HANDLE hProcess;
  NTSTATUS status;

  status = PsLookupProcessByProcessId(ULongToHandle(pid), &process);
  CHECK_NT_RETURN(status, "Failed to find process by PID: %lu (0x%X)", pid, status);

  status = ObOpenObjectByPointer(process, OBJ_KERNEL_HANDLE, nullptr, PROCESS_TERMINATE, *PsProcessType, KernelMode, &hProcess);
  CHECK_NT_RETURN_CLEANUP(status, ObDereferenceObject(process), "Failed to open process by PID: %lu (0x%X)", pid, status);

  status = ZwTerminateProcess(hProcess, STATUS_SUCCESS);
  CHECK_NT_RETURN_CLEANUP(status, (ZwClose(hProcess), ObDereferenceObject(process)), "Failed to terminate process by PID: %lu (0x%X)", pid, status);

  ZwClose(hProcess);
  ObDereferenceObject(process);
  LOG_INFO("Process by PID: %lu terminated successfully", pid);
  return status;
}

// Checks if a process is killable by its PID (it's not in the protected list and is not critical)
bool Utils::isProcessKillable(ULONG pid) {
  LOG_INFO("Checking if process by PID: %lu is killable", pid);

  // Check if the process is in the protected list (includes critical system processes)
  for (size_t i = 0; i < sizeof(PROTECTED_PROCESSES) / sizeof(PROTECTED_PROCESSES[0]); i++) {
    if (PROTECTED_PROCESSES[i] == pid) {
      LOG_WARNING("Process by PID: %lu is in the protected list and cannot be killed", pid);

      return false;
    }
  }

  PEPROCESS process;
  HANDLE hProcess;
  NTSTATUS status;
  ULONG isCritical = 0;
  ULONG returnLength = 0;

  status = PsLookupProcessByProcessId(ULongToHandle(pid), &process);
  CHECK_NT_RETURN_FALSE(status, "Failed to find process by PID: %lu (0x%X)", pid, status);

  status = ObOpenObjectByPointer(process, OBJ_KERNEL_HANDLE, nullptr, PROCESS_QUERY_INFORMATION, *PsProcessType, KernelMode, &hProcess);
  CHECK_NT_RETURN_FALSE_CLEANUP(status, ObDereferenceObject(process), "Failed to open process by PID: %lu for query (0x%X)", pid, status);

  status = ZwQueryInformationProcess(hProcess, ProcessBreakOnTermination, &isCritical, sizeof(isCritical), &returnLength);

  ZwClose(hProcess);
  ObDereferenceObject(process);

  if (!NT_SUCCESS(status)) {
    LOG_WARNING("Failed to query critical status for process by PID: %lu, status: 0x%X", pid, status);
    return false; // If we can't query, assume it's not killable
  }

  return isCritical == 0;
}

NTSTATUS Utils::initializeProcessNotifications() {
  if (g_IsInitialized) {
    return STATUS_SUCCESS;
  }

  InitializeListHead(&g_ProcessNotificationQueue);
  KeInitializeSpinLock(&g_QueueLock);

  NTSTATUS status = PsSetCreateProcessNotifyRoutineEx(Hooks::onProcessStart, FALSE);
  CHECK_NT_RETURN(status, "Failed to register process notify routine (0x%X)", status);

  g_IsInitialized = TRUE;
  LOG_INFO("Process notifications initialized successfully");
  return STATUS_SUCCESS;
}

VOID Utils::cleanupProcessNotifications() {
  if (!g_IsInitialized) {
    return;
  }

  LOG_INFO("Starting process notifications cleanup");

  // Unregister the callback first
  NTSTATUS status = PsSetCreateProcessNotifyRoutineEx(Hooks::onProcessStart, TRUE);
  if (!NT_SUCCESS(status)) {
    LOG_ERROR("Failed to unregister process notify routine, status: 0x%X", status);
  } else {
    LOG_INFO("Process notify routine unregistered successfully");
  }

  // Wait a bit to ensure no more callbacks are coming
  LARGE_INTEGER delay;
  delay.QuadPart = -10000 * 50; // 50ms delay
  KeDelayExecutionThread(KernelMode, FALSE, &delay);

  // Clean up the queue
  KIRQL oldIrql;
  KeAcquireSpinLock(&g_QueueLock, &oldIrql);

  ULONG notificationCount = 0;
  while (!IsListEmpty(&g_ProcessNotificationQueue)) {
    PLIST_ENTRY entry = RemoveHeadList(&g_ProcessNotificationQueue);
    PPROCESS_NOTIFICATION notification = CONTAINING_RECORD(entry, PROCESS_NOTIFICATION, ListEntry);
    ExFreePoolWithTag(notification, 'nPrP');
    notificationCount++;
  }

  KeReleaseSpinLock(&g_QueueLock, oldIrql);

  g_IsInitialized = FALSE;
  LOG_INFO("Process notifications cleaned up successfully, freed %lu notifications", notificationCount);
}

PVOID Utils::dequeueProcessNotification() {
  if (!g_IsInitialized) {
    return nullptr;
  }

  KIRQL oldIrql;
  PPROCESS_NOTIFICATION notification = nullptr;

  KeAcquireSpinLock(&g_QueueLock, &oldIrql);

  if (!IsListEmpty(&g_ProcessNotificationQueue)) {
    PLIST_ENTRY entry = RemoveHeadList(&g_ProcessNotificationQueue);
    notification = CONTAINING_RECORD(entry, PROCESS_NOTIFICATION, ListEntry);
  }

  KeReleaseSpinLock(&g_QueueLock, oldIrql);

  return notification;
}

VOID Utils::enqueueProcessNotification(PVOID notificationPtr) {
  if (!g_IsInitialized || notificationPtr == nullptr) {
    return;
  }

  auto notification = (PPROCESS_NOTIFICATION)notificationPtr;

  KIRQL oldIrql;
  KeAcquireSpinLock(&g_QueueLock, &oldIrql);
  InsertTailList(&g_ProcessNotificationQueue, &notification->ListEntry);
  KeReleaseSpinLock(&g_QueueLock, oldIrql);
}

// Suspends a process using PsSuspendProcess
NTSTATUS Utils::suspendProcess(HANDLE processId) {
  LOG_INFO("Suspending process by PID: %lu", HandleToULong(processId));

  PEPROCESS process;
  NTSTATUS status = PsLookupProcessByProcessId(processId, &process);
  CHECK_NT_RETURN(status, "Failed to find process by PID: %lu (0x%X)", HandleToULong(processId), status);

  status = PsSuspendProcess(process);
  ObDereferenceObject(process);
  CHECK_NT_RETURN(status, "Failed to suspend process PID: %lu (0x%X)", HandleToULong(processId), status);

  LOG_INFO("Successfully suspended process PID: %lu", HandleToULong(processId));
  return STATUS_SUCCESS;
}

// Resumes a process using PsResumeProcess
NTSTATUS Utils::resumeProcess(ULONG pid) {
  LOG_INFO("Resuming process by PID: %lu", pid);

  PEPROCESS process;
  NTSTATUS status = PsLookupProcessByProcessId(ULongToHandle(pid), &process);
  CHECK_NT_RETURN(status, "Failed to find process by PID: %lu (0x%X)", pid, status);

  status = PsResumeProcess(process);
  ObDereferenceObject(process);
  CHECK_NT_RETURN(status, "Failed to resume process PID: %lu (0x%X)", pid, status);

  LOG_INFO("Successfully resumed process PID: %lu", pid);
  return STATUS_SUCCESS;
}

BOOLEAN Utils::isValidUnicodeString(PCUNICODE_STRING unicodeString) {
  return (unicodeString != nullptr &&
          unicodeString->Buffer != nullptr &&
          unicodeString->Length > 0);
}
