#pragma once

#include "analysis_types.hpp"
#include "memory_dumper.hpp"

#include <filesystem>
#include <string>
#include <vector>

/**
 * @brief Limits used by raw-memory string extraction.
 */
struct StringScanOptions {
    /** @brief Minimal printable string length to write into reports. */
    int minLength = 6;

    /** @brief Hard cap for the total number of strings written to strings.tsv. */
    size_t maxStrings = 50000;
};

/**
 * @brief Counters collected while scanning memory dumps.
 */
struct StringScanSummary {
    /** @brief Number of ASCII strings written to the report. */
    size_t asciiStrings = 0;

    /** @brief Number of UTF-16LE strings written to the report. */
    size_t utf16Strings = 0;

    /** @brief Number of strings copied to hits.tsv because of suspicious terms. */
    size_t suspiciousHits = 0;
};

/**
 * @brief Raw-memory location of a value previously marked in JavaScript.
 */
struct TrackedLocation {
    /** @brief Mark label supplied by the analyzed script. */
    std::string name;

    /** @brief Printable bytes searched in the dump file. */
    std::string preview;

    /** @brief Encoding that matched the bytes, usually ascii or utf16le. */
    std::string encoding;

    /** @brief Dump file name where the value was found. */
    std::string dumpFile;

    /** @brief Virtual address corresponding to the match. */
    std::uint64_t address = 0;
};

/**
 * @brief Check one extracted string against built-in suspicious indicators.
 *
 * @param value String extracted from a dump.
 * @return True when value contains a keyword such as eval(, fetch(, http://,
 *         powershell, or ActiveXObject.
 */
bool isSuspiciousString(const std::string& value);

/**
 * @brief Extract printable ASCII and UTF-16LE strings from memory dumps.
 *
 * @param regions Dump files and original address ranges to scan.
 * @param stringsReport Path to the full TSV string report.
 * @param hitsReport Path to the TSV report containing suspicious strings only.
 * @param options Scan limits.
 * @return Counters describing the scan result.
 *
 * @throws std::runtime_error when an input or output file cannot be opened.
 */
StringScanSummary extractStrings(
    const std::vector<DumpedRegion>& regions,
    const std::filesystem::path& stringsReport,
    const std::filesystem::path& hitsReport,
    StringScanOptions options
);

/**
 * @brief Search raw dumps for values pinned through mark(name, value).
 *
 * @param regions Dump files and original address ranges to scan.
 * @param trackedValues Values collected by the JavaScript sandbox.
 * @param maxHitsPerValue Maximum number of addresses returned for each value.
 * @return Locations where tracked value previews were found.
 *
 * @throws std::runtime_error when a dump file cannot be opened.
 */
std::vector<TrackedLocation> locateTrackedValues(
    const std::vector<DumpedRegion>& regions,
    const std::vector<TrackedValue>& trackedValues,
    size_t maxHitsPerValue
);

/**
 * @brief Write tracked value locations as TSV.
 *
 * @param path Output TSV file path.
 * @param locations Locations to write.
 *
 * @throws std::runtime_error when the output file cannot be opened.
 */
void writeTrackedLocations(
    const std::filesystem::path& path,
    const std::vector<TrackedLocation>& locations
);
