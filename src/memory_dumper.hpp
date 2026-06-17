#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

/**
 * @brief One virtual memory mapping from a Linux /proc maps file.
 */
struct MemoryRegion {
    /** @brief Inclusive start address of the mapping. */
    std::uint64_t start = 0;

    /** @brief Exclusive end address of the mapping. */
    std::uint64_t end = 0;

    /** @brief Linux permission string, for example rw-p or r-xp. */
    std::string permissions;

    /** @brief Optional mapped file path or pseudo-name such as [heap]. */
    std::string path;

    /**
     * @brief Check whether the mapping has read permission.
     *
     * @return True when the first permission character is r.
     */
    bool readable() const;

    /**
     * @brief Compute the mapping size in bytes.
     *
     * @return end - start when the range is valid, otherwise zero.
     */
    std::uint64_t size() const;
};

/**
 * @brief Description of a memory region copied into an artifact file.
 */
struct DumpedRegion {
    /** @brief Original virtual memory mapping. */
    MemoryRegion region;

    /** @brief Path to the raw dump file on disk. */
    std::filesystem::path dumpFile;

    /** @brief Number of bytes actually read from the process. */
    std::uint64_t readableBytes = 0;
};

/**
 * @brief Convert a single line from a Linux maps file into a MemoryRegion.
 *
 * @param line Raw line from a maps file.
 * @return Parsed region, or std::nullopt for malformed input.
 */
std::optional<MemoryRegion> parseMemoryMapLine(const std::string& line);

/**
 * @brief Read memory maps and dump readable regions from the current process.
 */
class MemoryDumper {
public:
    /**
     * @brief Build the default Linux maps path.
     *
     * @return Path to the current process maps pseudo-file.
     */
    static std::filesystem::path defaultLinuxMapsPath();

    /**
     * @brief Create a dumper using a maps file path.
     *
     * @param mapsPath Path to a Linux maps-compatible file.
     */
    explicit MemoryDumper(std::filesystem::path mapsPath = defaultLinuxMapsPath());

    /**
     * @brief Parse all valid mappings from a maps-compatible file.
     *
     * @param mapsPath Path to a Linux maps-compatible file.
     * @return List of parsed memory regions.
     *
     * @throws std::runtime_error if the file cannot be opened.
     */
    static std::vector<MemoryRegion> readProcessMaps(const std::filesystem::path& mapsPath);

    /**
     * @brief Dump readable regions from the current process.
     *
     * @param outputDir Directory that receives raw region dump files.
     * @param includeFileBacked True to dump file-backed mappings as well as
     *        anonymous mappings.
     * @param maxRegionBytes Optional cap for bytes copied from each mapping.
     * @return Metadata for every dump file that was written.
     *
     * @throws std::runtime_error on unsupported platforms or filesystem errors.
     */
    std::vector<DumpedRegion> dumpReadableRegions(
        const std::filesystem::path& outputDir,
        bool includeFileBacked,
        std::optional<std::uint64_t> maxRegionBytes
    ) const;

private:
    static bool shouldDump(const MemoryRegion& region, bool includeFileBacked);

private:
    std::filesystem::path mapsPath_;
};

/**
 * @brief Format an address as a fixed-width hexadecimal string.
 *
 * @param value Address value.
 * @return Text in the form 0x0000000000000000.
 */
std::string hexAddress(std::uint64_t value);
