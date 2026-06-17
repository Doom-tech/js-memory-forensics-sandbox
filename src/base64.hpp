#pragma once

#include <string>

/**
 * @brief Decode an RFC 4648 base64 string in strict mode.
 *
 * @param encoded Input text. ASCII whitespace is ignored, padding is validated.
 * @return Decoded bytes stored in a std::string.
 *
 * @throws std::runtime_error if the input contains an invalid character or
 *         malformed padding.
 */
std::string decodeBase64Strict(const std::string& encoded);
