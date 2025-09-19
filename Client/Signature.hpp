#pragma once

#include <sstream>
#include <string>
#include <vector>

enum class SignatureType {
  String,
  Hex,
  FileHash
};

class Signature {
private:
  std::string _name;
  SignatureType _type;
  std::string _signatureString;
  std::vector<int> _signatureBytes; // -1 = any byte

public:
  Signature(const std::string &name, SignatureType type, const std::string &signatureString)
      : _name(name)
      , _type(type)
      , _signatureString(signatureString) {
    if (_type == SignatureType::Hex) {
      _parseHexSignature();
    }
  }

  std::string getName() const { return _name; }
  SignatureType getType() const { return _type; }
  std::string getSignatureString() const { return _signatureString; }
  std::vector<int> getSignatureBytes() const { return _signatureBytes; }

private:
  // The hex signature is built like this:
  // AA BB ?? CC
  // Which would match: AA BB FA CC
  // And would not match: AB BB FA CC
  void _parseHexSignature();
};
