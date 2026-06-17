#pragma once

#include <string>

/**
 * @brief Ограничения ресурсов для JavaScript-песочницы.
 */
struct SandboxConfig {
    /** @brief Максимальное время выполнения одного скрипта в миллисекундах. */
    int timeoutMs = 2000;

    /** @brief Лимит V8 old-space heap в мегабайтах. */
    int maxOldSpaceMb = 64;
};

/**
 * @brief JavaScript-значение, закреплённое через вызов mark(name, value).
 */
struct TrackedValue {
    /** @brief Имя или метка значения, которую передал аналитик. */
    std::string name;

    /** @brief Текстовое представление значения для поиска в raw memory dump. */
    std::string preview;

    /** @brief V8 identity hash для объектов или ноль для примитивных значений. */
    int identityHash = 0;
};

/**
 * @brief Результат компиляции и выполнения одного JavaScript-файла.
 */
struct ScriptResult {
    /** @brief true, если скрипт скомпилировался и завершился без исключения. */
    bool ok = false;

    /** @brief true, если выполнение остановил watchdog по таймауту. */
    bool timedOut = false;

    /** @brief Текстовый статус выполнения или сообщение об ошибке. */
    std::string message;
};
