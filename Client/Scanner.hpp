#pragma once

#include "Signature.hpp"
#include "Utils.hpp"
#include <vector>

class Scanner {
private:
  std::vector<uint8_t> _buffer;
  std::vector<Signature> _signatures;
  std::string _fileHash;

public:
  void addSignature(const Signature &signature) { _signatures.push_back(signature); }

  void loadFile(const std::string &filePath);

  std::pair<bool, std::string> scan();

private:
  bool _scanString(const Signature &signature);
  bool _scanHex(const Signature &signature);
  bool _scanFileHash(const Signature &signature);
};
