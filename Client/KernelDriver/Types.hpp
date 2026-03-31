#pragma once

#include <ntifs.h>

#ifndef MAX_PATH
#define MAX_PATH 260
#endif

#ifndef MAX_COMMANDLINE
#define MAX_COMMANDLINE 512
#endif

typedef struct _IOCTL_KILL_PROCESS_INPUT {
  ULONG ProcessId;
} IOCTL_KILL_PROCESS_INPUT;

typedef struct _IOCTL_RESUME_PROCESS_INPUT {
  ULONG ProcessId;
} IOCTL_RESUME_PROCESS_INPUT;

typedef struct _PROCESS_NOTIFICATION {
  ULONG ProcessId;
  ULONG ParentProcessId;
  WCHAR ImageFileName[MAX_PATH];
  WCHAR CommandLine[MAX_COMMANDLINE];
  BOOLEAN IsCreated; // TRUE = created, FALSE = terminated
  LIST_ENTRY ListEntry;
} PROCESS_NOTIFICATION, *PPROCESS_NOTIFICATION;

typedef struct _IOCTL_GET_PROCESS_NOTIFICATION_OUTPUT {
  ULONG ProcessId;
  ULONG ParentProcessId;
  WCHAR ImageFileName[MAX_PATH];
  WCHAR CommandLine[MAX_COMMANDLINE];
  BOOLEAN IsCreated;
} IOCTL_GET_PROCESS_NOTIFICATION_OUTPUT;