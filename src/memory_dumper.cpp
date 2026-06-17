#include "memory_dumper.hpp"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <utility>

#if defined(JSFS_LINUX)
#include <sys/uio.h>
#include <unistd.h>
#endif

namespace {

std::string trimLeft(std::string value) {
    auto it = std::find_if(value.begin(), value.end(), [](unsigned char ch) {
        return !std::isspace(ch);
    });
    value.erase(value.begin(), it);
    return value;
}

std::string safeFilePart(std::string value) {
    if (value.empty()) {
        return "anonymous";
    }

    for (char& ch : value) {
        if (!std::isalnum(static_cast<unsigned char>(ch)) && ch != '.' && ch != '_') {
            ch = '_';
        }
    }

    if (value.size() > 80) {
        value = value.substr(value.size() - 80);
    }

    return value;
}

bool looksFileBacked(const MemoryRegion& region) {
    return !region.path.empty() && region.path.front() != '[';
}

#if defined(JSFS_LINUX)
ssize_t readSelfMemory(std::uint64_t address, char* buffer, size_t size) {
    iovec local{};
    local.iov_base = buffer;
    local.iov_len = size;

    iovec remote{};
    remote.iov_base = reinterpret_cast<void*>(address);
    remote.iov_len = size;

    return process_vm_readv(getpid(), &local, 1, &remote, 1, 0);
}
#endif

} // namespace

bool MemoryRegion::readable() const {
    return !permissions.empty() && permissions[0] == 'r';
}

std::uint64_t MemoryRegion::size() const {
    return end > start ? end - start : 0;
}

std::optional<MemoryRegion> parseMemoryMapLine(const std::string& line) {
    std::istringstream input(line);
    std::string addressRange;
    std::string offset;
    std::string device;
    std::string inode;
    std::string path;

    MemoryRegion region;
    if (!(input >> addressRange >> region.permissions >> offset >> device >> inode)) {
        return std::nullopt;
    }

    const size_t dash = addressRange.find('-');
    if (dash == std::string::npos || dash == 0 || dash + 1 >= addressRange.size()) {
        return std::nullopt;
    }

    try {
        region.start = std::stoull(addressRange.substr(0, dash), nullptr, 16);
        region.end = std::stoull(addressRange.substr(dash + 1), nullptr, 16);
    } catch (const std::exception&) {
        return std::nullopt;
    }

    if (region.end < region.start) {
        return std::nullopt;
    }

    std::getline(input, path);
    region.path = trimLeft(path);
    return region;
}

std::filesystem::path MemoryDumper::defaultLinuxMapsPath() {
    return std::filesystem::path("/") / "proc" / "self" / "maps";
}

MemoryDumper::MemoryDumper(std::filesystem::path mapsPath) : mapsPath_(std::move(mapsPath)) {}

std::string hexAddress(std::uint64_t value) {
    std::ostringstream out;
    out << "0x" << std::hex << std::setw(16) << std::setfill('0') << value;
    return out.str();
}

std::vector<MemoryRegion> MemoryDumper::readProcessMaps(
    const std::filesystem::path& mapsPath
) {
    std::ifstream maps(mapsPath);
    if (!maps) {
        throw std::runtime_error("cannot open maps file: " + mapsPath.string());
    }

    std::vector<MemoryRegion> regions;
    std::string line;

    while (std::getline(maps, line)) {
        std::optional<MemoryRegion> region = parseMemoryMapLine(line);
        if (region.has_value()) {
            regions.push_back(*region);
        }
    }

    return regions;
}

std::vector<DumpedRegion> MemoryDumper::dumpReadableRegions(
    const std::filesystem::path& outputDir,
    bool includeFileBacked,
    std::optional<std::uint64_t> maxRegionBytes
) const {
#if !defined(JSFS_LINUX)
    (void)outputDir;
    (void)includeFileBacked;
    (void)maxRegionBytes;
    throw std::runtime_error("process memory dump is implemented for Linux only");
#else
    std::filesystem::create_directories(outputDir);

    std::vector<DumpedRegion> dumped;
    const std::vector<MemoryRegion> regions = readProcessMaps(mapsPath_);
    const size_t pageSize = static_cast<size_t>(sysconf(_SC_PAGESIZE));
    const std::vector<char> zeroPage(pageSize, 0);

    int index = 0;
    for (const MemoryRegion& region : regions) {
        if (!shouldDump(region, includeFileBacked)) {
            continue;
        }

        std::uint64_t bytesToDump = region.size();
        if (maxRegionBytes.has_value()) {
            bytesToDump = std::min(bytesToDump, *maxRegionBytes);
        }

        std::ostringstream fileName;
        fileName << "region_"
                 << std::setw(4) << std::setfill('0') << index++
                 << "_"
                 << std::hex << region.start
                 << "-"
                 << (region.start + bytesToDump)
                 << "_"
                 << safeFilePart(region.path)
                 << ".bin";

        const std::filesystem::path filePath = outputDir / fileName.str();
        std::ofstream out(filePath, std::ios::binary);
        if (!out) {
            throw std::runtime_error("cannot create dump file: " + filePath.string());
        }

        DumpedRegion info;
        info.region = region;
        info.dumpFile = filePath;

        std::vector<char> page(pageSize);
        for (std::uint64_t offset = 0; offset < bytesToDump; offset += pageSize) {
            const size_t want = static_cast<size_t>(
                std::min<std::uint64_t>(pageSize, bytesToDump - offset)
            );

            std::fill(page.begin(), page.end(), 0);
            const ssize_t got = readSelfMemory(region.start + offset, page.data(), want);

            if (got > 0) {
                out.write(page.data(), got);
                info.readableBytes += static_cast<std::uint64_t>(got);

                if (static_cast<size_t>(got) < want) {
                    const size_t missing = want - static_cast<size_t>(got);
                    out.write(zeroPage.data(), missing);
                }
            } else {
                out.write(zeroPage.data(), want);
            }

            if (!out) {
                throw std::runtime_error("cannot write dump file: " + filePath.string());
            }
        }

        dumped.push_back(info);
    }

    return dumped;
#endif
}

bool MemoryDumper::shouldDump(const MemoryRegion& region, bool includeFileBacked) {
    if (!region.readable() || region.size() == 0) {
        return false;
    }

    if (includeFileBacked) {
        return true;
    }

    if (!looksFileBacked(region)) {
        return true;
    }

    const std::string& path = region.path;
    return path.find("v8") != std::string::npos ||
           path.find("node") != std::string::npos ||
           path.find("js-memory-sandbox") != std::string::npos;
}
