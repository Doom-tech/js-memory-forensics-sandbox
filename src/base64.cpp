#include "base64.hpp"

#include <array>
#include <cctype>
#include <stdexcept>
#include <vector>

namespace {

constexpr int invalidBase64 = -1;
constexpr int paddingBase64 = -2;

std::array<int, 256> makeDecodeTable() {
    std::array<int, 256> table{};
    table.fill(invalidBase64);

    for (int ch = 'A'; ch <= 'Z'; ++ch) {
        table[static_cast<size_t>(ch)] = ch - 'A';
    }
    for (int ch = 'a'; ch <= 'z'; ++ch) {
        table[static_cast<size_t>(ch)] = 26 + ch - 'a';
    }
    for (int ch = '0'; ch <= '9'; ++ch) {
        table[static_cast<size_t>(ch)] = 52 + ch - '0';
    }

    table[static_cast<size_t>('+')] = 62;
    table[static_cast<size_t>('/')] = 63;
    table[static_cast<size_t>('=')] = paddingBase64;
    return table;
}

const std::array<int, 256>& decodeTable() {
    static const std::array<int, 256> table = makeDecodeTable();
    return table;
}

std::vector<int> normalizedBase64(const std::string& encoded) {
    std::vector<int> values;
    values.reserve(encoded.size());

    bool seenPadding = false;
    for (unsigned char ch : encoded) {
        if (std::isspace(ch)) {
            continue;
        }

        const int value = decodeTable()[static_cast<size_t>(ch)];
        if (value == invalidBase64) {
            throw std::runtime_error("invalid base64 character");
        }
        if (seenPadding && value != paddingBase64) {
            throw std::runtime_error("base64 data after padding");
        }
        if (value == paddingBase64) {
            seenPadding = true;
        }

        values.push_back(value);
    }

    if (values.empty()) {
        return values;
    }
    if (values.size() % 4 != 0) {
        throw std::runtime_error("base64 length is not a multiple of four");
    }

    return values;
}

} // namespace

std::string decodeBase64Strict(const std::string& encoded) {
    const std::vector<int> values = normalizedBase64(encoded);
    std::string decoded;
    decoded.reserve((values.size() / 4) * 3);

    for (size_t index = 0; index < values.size(); index += 4) {
        const int a = values[index];
        const int b = values[index + 1];
        const int c = values[index + 2];
        const int d = values[index + 3];

        if (a < 0 || b < 0) {
            throw std::runtime_error("base64 padding in the first two positions");
        }

        const unsigned int triple =
            (static_cast<unsigned int>(a) << 18) |
            (static_cast<unsigned int>(b) << 12) |
            (static_cast<unsigned int>(c > 0 ? c : 0) << 6) |
            static_cast<unsigned int>(d > 0 ? d : 0);

        decoded.push_back(static_cast<char>((triple >> 16) & 0xffU));

        if (c == paddingBase64) {
            if (d != paddingBase64 || index + 4 != values.size()) {
                throw std::runtime_error("invalid base64 padding");
            }
            continue;
        }
        decoded.push_back(static_cast<char>((triple >> 8) & 0xffU));

        if (d == paddingBase64) {
            if (index + 4 != values.size()) {
                throw std::runtime_error("invalid base64 padding");
            }
            continue;
        }
        decoded.push_back(static_cast<char>(triple & 0xffU));
    }

    return decoded;
}
