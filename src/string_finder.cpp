#include "string_finder.hpp"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace {

bool isPrintableAscii(unsigned char ch) {
    return ch >= 32 && ch <= 126;
}

std::string escaped(std::string text) {
    for (char& ch : text) {
        if (ch == '\t' || ch == '\n' || ch == '\r') {
            ch = ' ';
        }
    }

    constexpr size_t maxLen = 240;
    if (text.size() > maxLen) {
        text = text.substr(0, maxLen) + "...";
    }

    return text;
}

std::string lowerCopy(std::string text) {
    std::transform(text.begin(), text.end(), text.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return text;
}

const std::vector<std::string>& suspiciousKeywords() {
    static const std::vector<std::string> keywords = {
        "eval(",
        "function(",
        "atob(",
        "fromcharcode",
        "document.cookie",
        "xmlhttprequest",
        "fetch(",
        "http://",
        "https://",
        "powershell",
        "cmd.exe",
        "wscript.shell",
        "activexobject",
        "base64",
        "iframe",
        "unescape("
    };

    return keywords;
}

void writeFoundString(
    std::ofstream& strings,
    std::ofstream& hits,
    StringScanSummary& summary,
    const DumpedRegion& region,
    std::uint64_t offset,
    const std::string& encoding,
    const std::string& text
) {
    if (encoding == "ascii") {
        ++summary.asciiStrings;
    } else {
        ++summary.utf16Strings;
    }

    strings << hexAddress(region.region.start + offset) << '\t'
            << encoding << '\t'
            << region.dumpFile.filename().string() << '\t'
            << escaped(text) << '\n';

    if (isSuspiciousString(text)) {
        ++summary.suspiciousHits;
        hits << hexAddress(region.region.start + offset) << '\t'
             << encoding << '\t'
             << region.dumpFile.filename().string() << '\t'
             << escaped(text) << '\n';
    }
}

std::vector<unsigned char> asAsciiNeedle(const std::string& text) {
    return std::vector<unsigned char>(text.begin(), text.end());
}

std::vector<unsigned char> asUtf16LeNeedle(const std::string& text) {
    std::vector<unsigned char> bytes;
    bytes.reserve(text.size() * 2);
    for (unsigned char ch : text) {
        bytes.push_back(ch);
        bytes.push_back(0);
    }
    return bytes;
}

std::vector<std::uint64_t> findNeedleInFile(
    const std::filesystem::path& file,
    const std::vector<unsigned char>& needle,
    size_t maxHits
) {
    std::vector<std::uint64_t> hits;
    if (needle.empty() || maxHits == 0) {
        return hits;
    }

    std::ifstream input(file, std::ios::binary);
    if (!input) {
        throw std::runtime_error("cannot open dump file: " + file.string());
    }

    constexpr size_t chunkSize = 1024 * 1024;
    std::vector<unsigned char> chunk(chunkSize);
    std::vector<unsigned char> tail;
    std::uint64_t fileOffset = 0;
    std::uint64_t lastHit = static_cast<std::uint64_t>(-1);

    while (input) {
        input.read(reinterpret_cast<char*>(chunk.data()), chunk.size());
        const size_t got = static_cast<size_t>(input.gcount());
        if (got == 0) {
            break;
        }

        std::vector<unsigned char> window;
        window.reserve(tail.size() + got);
        window.insert(window.end(), tail.begin(), tail.end());
        window.insert(window.end(), chunk.begin(), chunk.begin() + got);

        const std::uint64_t windowBase = fileOffset - tail.size();
        auto it = window.begin();
        while (true) {
            it = std::search(it, window.end(), needle.begin(), needle.end());
            if (it == window.end()) {
                break;
            }

            const std::uint64_t hitOffset =
                windowBase + static_cast<std::uint64_t>(std::distance(window.begin(), it));

            if (hitOffset != lastHit) {
                hits.push_back(hitOffset);
                lastHit = hitOffset;
                if (hits.size() >= maxHits) {
                    return hits;
                }
            }

            ++it;
        }

        const size_t keep = std::min(needle.size() - 1, window.size());
        tail.assign(window.end() - static_cast<std::ptrdiff_t>(keep), window.end());
        fileOffset += got;
    }

    return hits;
}

std::string usefulPreview(std::string value) {
    value = escaped(value);
    if (value.size() < 4) {
        return "";
    }

    if (value.size() > 96) {
        value = value.substr(0, 96);
    }

    return value;
}

} // namespace

bool isSuspiciousString(const std::string& value) {
    const std::string lowered = lowerCopy(value);
    for (const std::string& keyword : suspiciousKeywords()) {
        if (lowered.find(keyword) != std::string::npos) {
            return true;
        }
    }
    return false;
}

StringScanSummary extractStrings(
    const std::vector<DumpedRegion>& regions,
    const std::filesystem::path& stringsReport,
    const std::filesystem::path& hitsReport,
    StringScanOptions options
) {
    if (options.minLength <= 0) {
        throw std::runtime_error("minimal string length must be positive");
    }

    std::ofstream strings(stringsReport);
    std::ofstream hits(hitsReport);
    if (!strings) {
        throw std::runtime_error("cannot create strings report: " + stringsReport.string());
    }
    if (!hits) {
        throw std::runtime_error("cannot create suspicious hits report: " + hitsReport.string());
    }

    strings << "address\tencoding\tregion\ttext\n";
    hits << "address\tencoding\tregion\ttext\n";

    StringScanSummary summary;
    size_t totalWritten = 0;

    for (const DumpedRegion& region : regions) {
        if (totalWritten >= options.maxStrings) {
            break;
        }

        std::ifstream input(region.dumpFile, std::ios::binary);
        if (!input) {
            throw std::runtime_error("cannot open dump file: " + region.dumpFile.string());
        }

        std::string current;
        std::uint64_t currentStart = 0;
        std::uint64_t offset = 0;
        char raw = 0;

        while (input.get(raw)) {
            const auto ch = static_cast<unsigned char>(raw);
            if (isPrintableAscii(ch)) {
                if (current.empty()) {
                    currentStart = offset;
                }
                current.push_back(static_cast<char>(ch));
            } else {
                if (static_cast<int>(current.size()) >= options.minLength) {
                    writeFoundString(strings, hits, summary, region, currentStart, "ascii", current);
                    ++totalWritten;
                    if (totalWritten >= options.maxStrings) {
                        break;
                    }
                }
                current.clear();
            }
            ++offset;
        }

        if (static_cast<int>(current.size()) >= options.minLength &&
            totalWritten < options.maxStrings) {
            writeFoundString(strings, hits, summary, region, currentStart, "ascii", current);
            ++totalWritten;
        }

        for (int alignment = 0; alignment <= 1 && totalWritten < options.maxStrings; ++alignment) {
            std::ifstream utf16(region.dumpFile, std::ios::binary);
            if (!utf16) {
                throw std::runtime_error("cannot open dump file: " + region.dumpFile.string());
            }

            utf16.seekg(alignment);
            std::string text;
            std::uint64_t textStart = static_cast<std::uint64_t>(alignment);
            std::uint64_t pairOffset = static_cast<std::uint64_t>(alignment);

            while (utf16) {
                char lo = 0;
                char hi = 0;
                utf16.get(lo);
                utf16.get(hi);
                if (!utf16) {
                    break;
                }

                const auto low = static_cast<unsigned char>(lo);
                const auto high = static_cast<unsigned char>(hi);
                if (high == 0 && isPrintableAscii(low)) {
                    if (text.empty()) {
                        textStart = pairOffset;
                    }
                    text.push_back(static_cast<char>(low));
                } else {
                    if (static_cast<int>(text.size()) >= options.minLength) {
                        writeFoundString(strings, hits, summary, region, textStart, "utf16le", text);
                        ++totalWritten;
                        if (totalWritten >= options.maxStrings) {
                            break;
                        }
                    }
                    text.clear();
                }

                pairOffset += 2;
            }

            if (static_cast<int>(text.size()) >= options.minLength &&
                totalWritten < options.maxStrings) {
                writeFoundString(strings, hits, summary, region, textStart, "utf16le", text);
                ++totalWritten;
            }
        }
    }

    if (!strings || !hits) {
        throw std::runtime_error("string report write failed");
    }

    return summary;
}

std::vector<TrackedLocation> locateTrackedValues(
    const std::vector<DumpedRegion>& regions,
    const std::vector<TrackedValue>& trackedValues,
    size_t maxHitsPerValue
) {
    std::vector<TrackedLocation> locations;
    if (maxHitsPerValue == 0) {
        return locations;
    }

    for (const TrackedValue& value : trackedValues) {
        const std::string preview = usefulPreview(value.preview);
        if (preview.empty()) {
            continue;
        }

        const std::vector<unsigned char> ascii = asAsciiNeedle(preview);
        const std::vector<unsigned char> utf16 = asUtf16LeNeedle(preview);

        size_t hitsForValue = 0;
        for (const DumpedRegion& region : regions) {
            if (hitsForValue >= maxHitsPerValue) {
                break;
            }

            for (std::uint64_t offset : findNeedleInFile(region.dumpFile, ascii, maxHitsPerValue)) {
                TrackedLocation location;
                location.name = value.name;
                location.preview = preview;
                location.encoding = "ascii";
                location.dumpFile = region.dumpFile.filename().string();
                location.address = region.region.start + offset;
                locations.push_back(location);

                if (++hitsForValue >= maxHitsPerValue) {
                    break;
                }
            }

            if (hitsForValue >= maxHitsPerValue) {
                break;
            }

            for (std::uint64_t offset : findNeedleInFile(region.dumpFile, utf16, maxHitsPerValue)) {
                TrackedLocation location;
                location.name = value.name;
                location.preview = preview;
                location.encoding = "utf16le";
                location.dumpFile = region.dumpFile.filename().string();
                location.address = region.region.start + offset;
                locations.push_back(location);

                if (++hitsForValue >= maxHitsPerValue) {
                    break;
                }
            }
        }
    }

    return locations;
}

void writeTrackedLocations(
    const std::filesystem::path& path,
    const std::vector<TrackedLocation>& locations
) {
    std::ofstream out(path);
    if (!out) {
        throw std::runtime_error("cannot create tracked locations report: " + path.string());
    }

    out << "name\taddress\tencoding\tregion\tpreview\n";

    for (const TrackedLocation& location : locations) {
        out << location.name << '\t'
            << hexAddress(location.address) << '\t'
            << location.encoding << '\t'
            << location.dumpFile << '\t'
            << escaped(location.preview) << '\n';
    }

    if (!out) {
        throw std::runtime_error("tracked locations report write failed: " + path.string());
    }
}
