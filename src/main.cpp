#include "js_sandbox.hpp"
#include "memory_dumper.hpp"
#include "string_finder.hpp"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

struct AppConfig {
    std::filesystem::path scriptPath;
    std::filesystem::path outputDir = "analysis_out";
    std::filesystem::path mapsPath = MemoryDumper::defaultLinuxMapsPath();
    int timeoutMs = 2000;
    int maxOldSpaceMb = 64;
    int minStringLength = 6;
    size_t maxStrings = 50000;
    bool includeFileBacked = true;
    bool dumpMemory = true;
    bool heapSnapshot = true;
    std::optional<std::uint64_t> maxRegionBytes;
};

bool startsWith(const std::string& value, const std::string& prefix) {
    return value.rfind(prefix, 0) == 0;
}

std::string valueAfterEquals(const std::string& argument) {
    const size_t pos = argument.find('=');
    if (pos == std::string::npos || pos + 1 >= argument.size()) {
        throw std::runtime_error("argument requires a value: " + argument);
    }
    return argument.substr(pos + 1);
}

int parsePositiveInt(const std::string& value, const std::string& name) {
    const int parsed = std::stoi(value);
    if (parsed <= 0) {
        throw std::runtime_error(name + " must be positive");
    }
    return parsed;
}

std::uint64_t parsePositiveBytesFromMiB(const std::string& value, const std::string& name) {
    const std::uint64_t parsed = std::stoull(value);
    if (parsed == 0) {
        throw std::runtime_error(name + " must be positive");
    }
    return parsed * 1024ULL * 1024ULL;
}

void printHelp() {
    std::cout
        << "Usage:\n"
        << "  js-memory-sandbox [options] suspicious.js\n\n"
        << "Options:\n"
        << "  --out=DIR                 Output directory, default analysis_out\n"
        << "  --timeout-ms=N            JS execution timeout, default 2000\n"
        << "  --max-old-space-mb=N      V8 old-space limit, default 64\n"
        << "  --min-string=N            Minimal extracted string length, default 6\n"
        << "  --max-strings=N           Max strings written to report, default 50000\n"
        << "  --max-region-mb=N         Dump at most N MiB from each memory region\n"
        << "  --maps=PATH               Linux maps file, default /proc/self/maps\n"
        << "  --skip-file-backed        Dump anonymous/heap/stack/V8-like regions only\n"
        << "  --no-memory-dump          Run JS and write heap snapshot only\n"
        << "  --no-heap-snapshot        Skip V8 heap snapshot\n";
}

AppConfig parseArgs(int argc, char** argv) {
    AppConfig config;

    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];

        if (arg == "--help" || arg == "-h") {
            printHelp();
            std::exit(0);
        } else if (startsWith(arg, "--out=")) {
            config.outputDir = valueAfterEquals(arg);
        } else if (startsWith(arg, "--timeout-ms=")) {
            config.timeoutMs = parsePositiveInt(valueAfterEquals(arg), "timeout");
        } else if (startsWith(arg, "--max-old-space-mb=")) {
            config.maxOldSpaceMb = parsePositiveInt(valueAfterEquals(arg), "V8 old-space limit");
        } else if (startsWith(arg, "--min-string=")) {
            config.minStringLength = parsePositiveInt(valueAfterEquals(arg), "minimal string length");
        } else if (startsWith(arg, "--max-strings=")) {
            config.maxStrings = static_cast<size_t>(std::stoull(valueAfterEquals(arg)));
            if (config.maxStrings == 0) {
                throw std::runtime_error("max strings must be positive");
            }
        } else if (startsWith(arg, "--max-region-mb=")) {
            config.maxRegionBytes = parsePositiveBytesFromMiB(valueAfterEquals(arg), "max region size");
        } else if (startsWith(arg, "--maps=")) {
            config.mapsPath = valueAfterEquals(arg);
        } else if (arg == "--skip-file-backed") {
            config.includeFileBacked = false;
        } else if (arg == "--no-memory-dump") {
            config.dumpMemory = false;
        } else if (arg == "--no-heap-snapshot") {
            config.heapSnapshot = false;
        } else if (!startsWith(arg, "--")) {
            config.scriptPath = arg;
        } else {
            throw std::runtime_error("unknown argument: " + arg);
        }
    }

    if (config.scriptPath.empty()) {
        throw std::runtime_error("script path is required");
    }

    return config;
}

void writeMainReport(
    const AppConfig& config,
    const ScriptResult& scriptResult,
    const std::vector<DumpedRegion>& dumpedRegions,
    const StringScanSummary& scanSummary,
    const std::vector<TrackedValue>& trackedValues,
    const std::vector<TrackedLocation>& trackedLocations,
    bool heapSnapshotWritten,
    const std::string& heapSnapshotError,
    const std::string& memoryDumpError,
    const std::string& stringExtractionError,
    const std::string& trackedLocationError
) {
    const std::filesystem::path reportPath = config.outputDir / "report.md";
    std::ofstream report(reportPath);
    if (!report) {
        throw std::runtime_error("cannot create main report: " + reportPath.string());
    }

    report << "# JS Memory Forensics Sandbox Report\n\n";
    report << "## Input\n\n";
    report << "- Script: `" << config.scriptPath.generic_string() << "`\n";
    report << "- Maps file: `" << config.mapsPath.generic_string() << "`\n";
    report << "- Timeout: `" << config.timeoutMs << " ms`\n";
    report << "- V8 max old space: `" << config.maxOldSpaceMb << " MiB`\n\n";

    report << "## Execution\n\n";
    report << "- Status: `" << (scriptResult.ok ? "ok" : "not ok") << "`\n";
    report << "- Timed out: `" << (scriptResult.timedOut ? "yes" : "no") << "`\n";
    report << "- Message: `" << scriptResult.message << "`\n\n";

    report << "## Memory Dump\n\n";
    report << "- Dumped regions: `" << dumpedRegions.size() << "`\n";
    std::uint64_t totalReadable = 0;
    for (const DumpedRegion& region : dumpedRegions) {
        totalReadable += region.readableBytes;
    }
    report << "- Readable bytes copied: `" << totalReadable << "`\n";
    report << "- File-backed mappings included: `"
           << (config.includeFileBacked ? "yes" : "no") << "`\n\n";
    if (!memoryDumpError.empty()) {
        report << "- Memory dump error: `" << memoryDumpError << "`\n\n";
    }

    report << "## Extracted Strings\n\n";
    report << "- ASCII strings: `" << scanSummary.asciiStrings << "`\n";
    report << "- UTF-16LE strings: `" << scanSummary.utf16Strings << "`\n";
    report << "- Suspicious keyword hits: `" << scanSummary.suspiciousHits << "`\n\n";
    if (!stringExtractionError.empty()) {
        report << "- String extraction error: `" << stringExtractionError << "`\n\n";
    }

    report << "## Tracked JS Values\n\n";
    if (trackedValues.empty()) {
        report << "The script did not call `mark(name, value)`.\n\n";
    } else {
        for (const TrackedValue& value : trackedValues) {
            report << "- `" << value.name << "`: `" << value.preview << "`";
            if (value.identityHash != 0) {
                report << ", identity hash `" << value.identityHash << "`";
            }
            report << "\n";
        }
        report << "\nTracked value memory hits: `" << trackedLocations.size() << "`\n\n";
    }
    if (!trackedLocationError.empty()) {
        report << "- Tracked value lookup error: `" << trackedLocationError << "`\n\n";
    }

    report << "## Artifacts\n\n";
    report << "- `strings.tsv`: extracted ASCII and UTF-16LE strings\n";
    report << "- `hits.tsv`: suspicious strings filtered by keywords\n";
    report << "- `tracked_locations.tsv`: marked JS values found in raw dumps\n";
    report << "- `memory/`: raw memory region dumps\n";
    if (heapSnapshotWritten) {
        report << "- `heap_snapshot.json`: V8 heap snapshot\n";
    } else if (!heapSnapshotError.empty()) {
        report << "- Heap snapshot error: `" << heapSnapshotError << "`\n";
    }

    if (!report) {
        throw std::runtime_error("main report write failed: " + reportPath.string());
    }
}

} // namespace

int main(int argc, char** argv) {
    try {
        AppConfig app = parseArgs(argc, argv);
        app.outputDir = std::filesystem::absolute(app.outputDir).lexically_normal();
        std::filesystem::create_directories(app.outputDir);

        V8Runtime runtime(argv[0], app.maxOldSpaceMb);
        JsSandbox sandbox({app.timeoutMs, app.maxOldSpaceMb});

        std::cout << "[*] Running script in restricted V8 context\n";
        ScriptResult result;
        bool scriptWasLoaded = false;
        try {
            result = sandbox.executeFile(app.scriptPath.string());
            scriptWasLoaded = true;
        } catch (const std::exception& error) {
            result.ok = false;
            result.message = error.what();
        }
        std::cout << "[*] " << result.message << "\n";

        std::vector<DumpedRegion> dumpedRegions;
        std::string memoryDumpError;
        if (app.dumpMemory && scriptWasLoaded) {
            std::cout << "[*] Dumping readable memory regions\n";
            try {
                MemoryDumper dumper(app.mapsPath);
                dumpedRegions = dumper.dumpReadableRegions(
                    app.outputDir / "memory",
                    app.includeFileBacked,
                    app.maxRegionBytes
                );
                std::cout << "[*] Dumped regions: " << dumpedRegions.size() << "\n";
            } catch (const std::exception& error) {
                memoryDumpError = error.what();
                std::cout << "[!] Memory dump was not written: " << memoryDumpError << "\n";
            }
        } else if (app.dumpMemory && !scriptWasLoaded) {
            memoryDumpError = "script was not loaded, memory dump was skipped";
        }

        bool heapSnapshotWritten = false;
        std::string heapSnapshotError;
        if (app.heapSnapshot) {
            std::cout << "[*] Writing V8 heap snapshot\n";
            try {
                sandbox.writeHeapSnapshot((app.outputDir / "heap_snapshot.json").string());
                heapSnapshotWritten = true;
            } catch (const std::exception& error) {
                heapSnapshotError = error.what();
                std::cout << "[!] Heap snapshot was not written: " << heapSnapshotError << "\n";
            }
        }

        StringScanSummary scanSummary;
        std::vector<TrackedLocation> trackedLocations;
        std::string stringExtractionError;
        std::string trackedLocationError;
        std::cout << "[*] Writing string and tracked-value reports\n";
        if (dumpedRegions.empty()) {
            try {
                scanSummary = extractStrings(
                    dumpedRegions,
                    app.outputDir / "strings.tsv",
                    app.outputDir / "hits.tsv",
                    {app.minStringLength, app.maxStrings}
                );
            } catch (const std::exception& error) {
                stringExtractionError = error.what();
                std::cout << "[!] Empty string reports were not written: "
                          << stringExtractionError << "\n";
            }

            try {
                writeTrackedLocations(app.outputDir / "tracked_locations.tsv", {});
            } catch (const std::exception& error) {
                trackedLocationError = error.what();
                std::cout << "[!] Empty tracked value report was not written: "
                          << trackedLocationError << "\n";
            }
        } else {
            std::cout << "[*] Extracting strings from memory dumps\n";
            try {
                scanSummary = extractStrings(
                    dumpedRegions,
                    app.outputDir / "strings.tsv",
                    app.outputDir / "hits.tsv",
                    {app.minStringLength, app.maxStrings}
                );
            } catch (const std::exception& error) {
                stringExtractionError = error.what();
                std::cout << "[!] String extraction failed: " << stringExtractionError << "\n";
            }

            try {
                trackedLocations = locateTrackedValues(
                    dumpedRegions,
                    sandbox.trackedValues(),
                    8
                );
                writeTrackedLocations(app.outputDir / "tracked_locations.tsv", trackedLocations);
            } catch (const std::exception& error) {
                trackedLocationError = error.what();
                std::cout << "[!] Tracked value lookup failed: " << trackedLocationError << "\n";
            }
        }

        writeMainReport(
            app,
            result,
            dumpedRegions,
            scanSummary,
            sandbox.trackedValues(),
            trackedLocations,
            heapSnapshotWritten,
            heapSnapshotError,
            memoryDumpError,
            stringExtractionError,
            trackedLocationError
        );

        std::cout << "[*] Report: " << (app.outputDir / "report.md").string() << "\n";
        return result.ok && memoryDumpError.empty() &&
                       stringExtractionError.empty() && trackedLocationError.empty()
                   ? 0
                   : 2;
    } catch (const std::exception& error) {
        std::cerr << "error: " << error.what() << "\n";
        printHelp();
        return 1;
    }
}
