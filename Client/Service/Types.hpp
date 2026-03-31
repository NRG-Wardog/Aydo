#pragma once

#include <windows.h>

#ifndef MAX_PATH
#define MAX_PATH 260
#endif

#ifndef MAX_COMMANDLINE
#define MAX_COMMANDLINE 512
#endif

typedef struct IOCTL_KILL_PROCESS_INPUT {
  ULONG ProcessId;
} IOCTL_KILL_PROCESS_INPUT;

typedef struct IOCTL_RESUME_PROCESS_INPUT {
  ULONG ProcessId;
} IOCTL_RESUME_PROCESS_INPUT;

typedef struct IOCTL_GET_PROCESS_NOTIFICATION_OUTPUT {
  ULONG ProcessId;
  ULONG ParentProcessId;
  WCHAR ImageFileName[MAX_PATH];
  WCHAR CommandLine[MAX_COMMANDLINE];
  BOOLEAN IsCreated; // TRUE = created, FALSE = terminated
} IOCTL_GET_PROCESS_NOTIFICATION_OUTPUT;
