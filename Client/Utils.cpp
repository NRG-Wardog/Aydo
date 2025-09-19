#include "Utils.hpp"

std::string Utils::calculateHash(std::vector<uint8_t> data) {
  auto hashFunction = Botan::HashFunction::create_or_throw("SHA-256");
  hashFunction->update(data);

  return Botan::hex_encode(hashFunction->final());
}

std::vector<RunningProcess> Utils::getRunningProcesses() {
  std::vector<RunningProcess> processes;

  HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (hProcessSnap == INVALID_HANDLE_VALUE) {
    return processes;
  }

  PROCESSENTRY32W pe32;
  pe32.dwSize = sizeof(PROCESSENTRY32W);

  if (!Process32FirstW(hProcessSnap, &pe32)) {
    CloseHandle(hProcessSnap);
    return processes;
  }

  do {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
    if (hProcess != NULL) {
      WCHAR path[MAX_PATH * 2] = {0};
      DWORD size = MAX_PATH * 2;

      if (QueryFullProcessImageNameW(hProcess, 0, path, &size)) {
        RunningProcess proc;
        proc.pid = pe32.th32ProcessID;

        int size_needed = WideCharToMultiByte(CP_UTF8, 0, path, -1, NULL, 0, NULL, NULL);
        std::string strTo(size_needed, 0);
        WideCharToMultiByte(CP_UTF8, 0, path, -1, &strTo[0], size_needed, NULL, NULL);
        strTo.resize(size_needed - 1); // remove null terminator

        proc.path = strTo;
        processes.push_back(proc);
      }
      CloseHandle(hProcess);
    }
  } while (Process32NextW(hProcessSnap, &pe32));

  CloseHandle(hProcessSnap);
  return processes;
}

unsigned int Utils::getCurrentProcessID() {
  return GetCurrentProcessId();
}
