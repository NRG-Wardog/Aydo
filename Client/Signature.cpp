#include "Signature.hpp"

void Signature::_parseHexSignature() {
    std::istringstream stream(_signatureString);
    std::string token;

    while (stream >> token) {
      if (token == "?" || token == "??") {
        _signatureBytes.push_back(-1);
      } else {
        _signatureBytes.push_back(std::stoi(token, nullptr, 16));
      }
    }
  }
