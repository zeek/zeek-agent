#pragma once

#include <string>

namespace zeek {
/// \brief Converts a single hex digit to a byte value
/// \param output Where the output byte is stored
/// \param input A hex digit, from 0 to 9, from A to F
/// \return True in case of success or false otherwise
bool convertHexDigitToByte(char &output, const char &input);

/// \brief Converts a hex string to a string
/// \param output Where the output string is stored
/// \param buffer A hex string with no spaces between each byte (i.e.:
/// 001122AABBCC) \return True in case of success or false otherwise
bool convertHexString(std::string &output, const std::string &buffer);

/// \brief Converts an Audit string to a normal string
/// \param output Where the output string is stored
/// \param buffer Either a normal (but quoted) string, or a hex string
/// \return True in case of success or false otherwise
bool convertAuditString(std::string &output, const std::string &buffer);
} // namespace zeek
