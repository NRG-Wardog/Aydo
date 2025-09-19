#include <botan/hash.h>
#include <botan/hex.h>
#include <fstream>
#include <iostream>
#include <vector>
#include <Windows.h>

#include "Scanner.hpp"
#include "Signature.hpp"
#include "Utils.hpp"

#define IOCTL_KILL_PROCESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0001, METHOD_NEITHER, FILE_SPECIAL_ACCESS)

struct KillProcessRequest {
  ULONG TargetPID;
};

int main() {
  std::vector<unsigned int> trustedProcessesPIDs;
  Scanner scanner;

  scanner.addSignature(Signature("ExampleVirus", SignatureType::String, "I'M AN EVIL VIRUS"));

  HANDLE hDevice = CreateFile(L"\\\\.\\AydoPOC", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
  if (hDevice == INVALID_HANDLE_VALUE) {
    std::cerr << "Failed to open device" << std::endl;
    return 1;
  }
  std::cout << "[DEBUG] Device opened successfully" << std::endl;

  unsigned int currentProcessID = Utils::getCurrentProcessID();

  while (true) {
    for (auto &process : Utils::getRunningProcesses()) {
      if (process.pid == currentProcessID || std::find(trustedProcessesPIDs.begin(), trustedProcessesPIDs.end(), process.pid) != trustedProcessesPIDs.end()) {
        std::cout << "[DEBUG] Process " << process.pid << " is trusted, skipping scan\n";
        continue;
      }

      scanner.loadFile(process.path);

      auto scanResult = scanner.scan();
      bool isVirus = scanResult.first;
      std::string virusName = scanResult.second;

      if (!isVirus) {
        std::cout << "[DEBUG] Adding pid " << process.pid << " to trusted processes\n";
        trustedProcessesPIDs.push_back(process.pid);
      } else {
        std::cout << "[DEBUG] Found virus " << virusName << " in process " << process.pid << "! Terminating process...\n";

        KillProcessRequest killProcessRequest{
            .TargetPID = (ULONG)process.pid};

        if (!DeviceIoControl(hDevice, IOCTL_KILL_PROCESS, &killProcessRequest, sizeof(killProcessRequest), NULL, 0, NULL, NULL)) {
          std::cerr << "Failed to kill process" << std::endl;
          return 1;
        }
      }
    }

    Sleep(1000);
  }

  CloseHandle(hDevice);

  return 0;
}
