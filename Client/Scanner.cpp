#include "Scanner.hpp"

void Scanner::loadFile(const std::string &filePath) {
  std::ifstream file(filePath, std::ios::binary);
  if (!file) {
    throw std::runtime_error("Failed to open file");
  }

  _buffer = std::vector<uint8_t>((std::istreambuf_iterator<char>(file)), (std::istreambuf_iterator<char>()));
  _fileHash = Utils::calculateHash(_buffer);
}

// Scans a buffer, and returns the first signature that matches
// <weather or not it matches>, <which signature matched it>
std::pair<bool, std::string> Scanner::scan() {
  for (const auto &signature : _signatures) {
    if (signature.getType() == SignatureType::String) {
      if (_scanString(signature)) {
        return std::make_pair(true, signature.getName());
      }
    } else if (signature.getType() == SignatureType::Hex) {
      if (_scanHex(signature)) {
        return std::make_pair(true, signature.getName());
      }
    } else if (signature.getType() == SignatureType::FileHash) {
      if (_scanFileHash(signature)) {
        return std::make_pair(true, signature.getName());
      }
    }
  }

  return std::make_pair(false, "");
}

//
// * NOTE: Currently the signature scanning is kinda slow and inefficient, but it's fine, because we're only in the POC stage.
// * AFTER the POC stage, we'll recrate it much more efficiently.
//

bool Scanner::_scanString(const Signature &signature) {
  std::string data(_buffer.begin(), _buffer.end());

  auto pos = data.find(signature.getSignatureString());

  return pos != std::string::npos;
}

bool Scanner::_scanHex(const Signature &signature) {
  unsigned int len = signature.getSignatureBytes().size();

  for (unsigned int i = 0; i < _buffer.size() - len; i++) {
    bool match = true;
    for (unsigned int j = 0; j < len; j++) {
      int byte = signature.getSignatureBytes()[j];

      if (byte == -1)
        continue; // Any byte

      if (byte != _buffer[i + j]) {
        match = false;
        break;
      }
    }
    if (match) {
      return true;
    }
  }

  return false;
}

bool Scanner::_scanFileHash(const Signature &signature) {
  return _fileHash == signature.getSignatureString();
}
