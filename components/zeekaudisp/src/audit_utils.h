#pragma once

#include <string>

namespace zeek {
bool convertHexDigitToByte(char &output, const char &input);
bool convertHexString(std::string &output, const std::string &buffer);
bool convertAuditString(std::string &output, const std::string &buffer);
} // namespace zeek
