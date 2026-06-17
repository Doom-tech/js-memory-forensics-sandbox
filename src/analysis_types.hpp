#pragma once

#include <string>

/**
 * @brief Runtime limits for the JavaScript sandbox.
 */
struct SandboxConfig {
    /** @brief Maximum wall-clock execution time for one script, in milliseconds. */
    int timeoutMs = 2000;

    /** @brief V8 old-space limit in MiB. */
    int maxOldSpaceMb = 64;
};

/**
 * @brief JavaScript value pinned by the analyzed script through mark(name, value).
 */
struct TrackedValue {
    /** @brief Analyst-supplied label for the value. */
    std::string name;

    /** @brief Printable representation used for raw-memory lookup. */
    std::string preview;

    /** @brief V8 identity hash for objects, or zero for primitive values. */
    int identityHash = 0;
};

/**
 * @brief Result of compiling and executing one JavaScript file.
 */
struct ScriptResult {
    /** @brief True when the script compiled and finished without an exception. */
    bool ok = false;

    /** @brief True when execution was interrupted by the watchdog timeout. */
    bool timedOut = false;

    /** @brief Human-readable status or exception text. */
    std::string message;
};
