#include <iostream>
#include <Windows.h>

int main() {
  std::cout << "I'M AN EVIL VIRUS" << std::endl;

  while (true) {
    std::cout << "Still running!" << std::endl;

    Sleep(1000);
  }
}