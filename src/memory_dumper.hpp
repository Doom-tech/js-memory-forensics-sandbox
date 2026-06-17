#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

/**
 * @brief Один виртуальный memory mapping из Linux-файла `/proc/.../maps`.
 */
struct MemoryRegion {
    /** @brief Начальный виртуальный адрес региона включительно. */
    std::uint64_t start = 0;

    /** @brief Конечный виртуальный адрес региона, не включая сам адрес end. */
    std::uint64_t end = 0;

    /** @brief Строка прав доступа Linux, например `rw-p` или `r-xp`. */
    std::string permissions;

    /** @brief Путь к отображённому файлу или псевдоимя региона, например `[heap]`. */
    std::string path;

    /**
     * @brief Проверяет, можно ли читать регион памяти.
     *
     * @return true, если первый символ permissions равен `r`.
     */
    bool readable() const;

    /**
     * @brief Считает размер региона в байтах.
     *
     * @return `end - start` для корректного диапазона, иначе ноль.
     */
    std::uint64_t size() const;
};

/**
 * @brief Описание региона памяти, который был скопирован в artifact-файл.
 */
struct DumpedRegion {
    /** @brief Исходный виртуальный регион памяти процесса. */
    MemoryRegion region;

    /** @brief Путь к raw dump-файлу на диске. */
    std::filesystem::path dumpFile;

    /** @brief Количество байтов, которые удалось прочитать из процесса. */
    std::uint64_t readableBytes = 0;
};

/**
 * @brief Парсит одну строку Linux maps-файла в структуру MemoryRegion.
 *
 * @param line Сырая строка из `/proc/self/maps` или совместимого файла.
 * @return Распарсенный регион или std::nullopt, если строка битая.
 */
std::optional<MemoryRegion> parseMemoryMapLine(const std::string& line);

/**
 * @brief Читает карту памяти процесса и дампит доступные для чтения регионы.
 */
class MemoryDumper {
public:
    /**
     * @brief Возвращает стандартный путь к maps-файлу текущего Linux-процесса.
     *
     * @return Путь `/proc/self/maps`, собранный без захардкоженных разделителей.
     */
    static std::filesystem::path defaultLinuxMapsPath();

    /**
     * @brief Создаёт dumper с заданным maps-файлом.
     *
     * @param mapsPath Путь к Linux maps-совместимому файлу.
     */
    explicit MemoryDumper(std::filesystem::path mapsPath = defaultLinuxMapsPath());

    /**
     * @brief Читает все корректные регионы из maps-файла.
     *
     * Битые строки пропускаются, потому что в тестах и ручном анализе удобнее
     * получить максимум валидных регионов, а не падать из-за одной плохой строки.
     *
     * @param mapsPath Путь к Linux maps-совместимому файлу.
     * @return Список распарсенных регионов памяти.
     *
     * @throws std::runtime_error если maps-файл нельзя открыть.
     */
    static std::vector<MemoryRegion> readProcessMaps(const std::filesystem::path& mapsPath);

    /**
     * @brief Дампит readable-регионы памяти текущего процесса.
     *
     * @param outputDir Папка, куда будут записаны raw dump-файлы.
     * @param includeFileBacked true, если нужно дампить не только anonymous
     *        regions, но и file-backed mappings библиотек/бинарей.
     * @param maxRegionBytes Необязательный лимит байтов для каждого региона.
     * @return Метаданные для каждого записанного dump-файла.
     *
     * @throws std::runtime_error если платформа не поддерживается или произошла
     *         ошибка файловой системы.
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
 * @brief Форматирует адрес как шестнадцатеричную строку фиксированной ширины.
 *
 * @param value Числовое значение адреса.
 * @return Строка вида `0x0000000000000000`.
 */
std::string hexAddress(std::uint64_t value);
