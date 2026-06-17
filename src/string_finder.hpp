#pragma once

#include "analysis_types.hpp"
#include "memory_dumper.hpp"

#include <filesystem>
#include <string>
#include <vector>

/**
 * @brief Настройки извлечения строк из raw memory dump.
 */
struct StringScanOptions {
    /** @brief Минимальная длина печатной строки, которая попадёт в отчёт. */
    int minLength = 6;

    /** @brief Максимальное количество строк, записываемых в `strings.tsv`. */
    size_t maxStrings = 50000;
};

/**
 * @brief Счётчики, собранные во время сканирования дампов памяти.
 */
struct StringScanSummary {
    /** @brief Количество ASCII-строк, записанных в отчёт. */
    size_t asciiStrings = 0;

    /** @brief Количество UTF-16LE-строк, записанных в отчёт. */
    size_t utf16Strings = 0;

    /** @brief Количество строк, попавших в `hits.tsv` из-за подозрительных слов. */
    size_t suspiciousHits = 0;
};

/**
 * @brief Место в raw dump, где найдено значение, ранее отмеченное в JavaScript.
 */
struct TrackedLocation {
    /** @brief Метка, которую скрипт передал в `mark(name, value)`. */
    std::string name;

    /** @brief Короткое текстовое представление значения, которое искали в дампе. */
    std::string preview;

    /** @brief Кодировка найденных байтов: обычно `ascii` или `utf16le`. */
    std::string encoding;

    /** @brief Имя dump-файла, где найдено совпадение. */
    std::string dumpFile;

    /** @brief Виртуальный адрес процесса, соответствующий найденному совпадению. */
    std::uint64_t address = 0;
};

/**
 * @brief Проверяет извлечённую строку по встроенным подозрительным индикаторам.
 *
 * @param value Строка, извлечённая из memory dump.
 * @return true, если строка содержит индикаторы вроде `eval(`, `fetch(`,
 *         `http://`, `powershell` или `ActiveXObject`.
 */
bool isSuspiciousString(const std::string& value);

/**
 * @brief Извлекает печатные ASCII и UTF-16LE строки из файлов дампа памяти.
 *
 * @param regions Метаданные dump-файлов и их исходные адресные диапазоны.
 * @param stringsReport Путь к TSV-отчёту со всеми найденными строками.
 * @param hitsReport Путь к TSV-отчёту только с подозрительными строками.
 * @param options Ограничения сканирования.
 * @return Счётчики найденных строк и подозрительных совпадений.
 *
 * @throws std::runtime_error если входной dump-файл или выходной отчёт нельзя
 *         открыть.
 */
StringScanSummary extractStrings(
    const std::vector<DumpedRegion>& regions,
    const std::filesystem::path& stringsReport,
    const std::filesystem::path& hitsReport,
    StringScanOptions options
);

/**
 * @brief Ищет в raw dump значения, закреплённые через `mark(name, value)`.
 *
 * Значение ищется в двух вариантах: как ASCII-байты и как UTF-16LE. Это помогает
 * находить строки, которые V8 хранит в разных внутренних представлениях.
 *
 * @param regions Метаданные dump-файлов и их исходные адресные диапазоны.
 * @param trackedValues Значения, собранные JavaScript-песочницей.
 * @param maxHitsPerValue Максимальное количество адресов для одного значения.
 * @return Список мест, где были найдены bytes preview отмеченных значений.
 *
 * @throws std::runtime_error если dump-файл нельзя открыть.
 */
std::vector<TrackedLocation> locateTrackedValues(
    const std::vector<DumpedRegion>& regions,
    const std::vector<TrackedValue>& trackedValues,
    size_t maxHitsPerValue
);

/**
 * @brief Записывает найденные адреса отмеченных значений в TSV-файл.
 *
 * @param path Путь к выходному TSV-файлу.
 * @param locations Список найденных совпадений.
 *
 * @throws std::runtime_error если выходной файл нельзя открыть или записать.
 */
void writeTrackedLocations(
    const std::filesystem::path& path,
    const std::vector<TrackedLocation>& locations
);
