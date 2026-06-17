#pragma once

#include "analysis_types.hpp"

#include <memory>
#include <string>
#include <vector>

/**
 * @brief Process-wide V8 initialization guard.
 *
 * Construct this object before creating JsSandbox instances and keep it alive
 * until every sandbox has been destroyed.
 */
class V8Runtime {
public:
    /**
     * @brief Initialize V8 and set the old-space limit.
     *
     * @param executablePath Path to the current executable, used by V8 for ICU
     *        and startup data discovery.
     * @param maxOldSpaceMb Maximum old-space size in MiB.
     *
     * @throws std::runtime_error if the project was built without V8 support.
     */
    V8Runtime(const char* executablePath, int maxOldSpaceMb);

    /**
     * @brief Shut down V8 platform state owned by this process.
     */
    ~V8Runtime();

    V8Runtime(const V8Runtime&) = delete;
    V8Runtime& operator=(const V8Runtime&) = delete;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

/**
 * @brief Restricted JavaScript executor used for memory-forensics analysis.
 *
 * The sandbox exposes only small helper functions: print, mark, and atob. It
 * does not expose Node.js objects, filesystem APIs, networking APIs, or process
 * globals.
 */
class JsSandbox {
public:
    /**
     * @brief Create an isolated JavaScript context.
     *
     * @param config Runtime limits for this context.
     *
     * @throws std::runtime_error if V8 support is unavailable.
     */
    explicit JsSandbox(SandboxConfig config);

    /**
     * @brief Dispose the isolated JavaScript context.
     */
    ~JsSandbox();

    JsSandbox(const JsSandbox&) = delete;
    JsSandbox& operator=(const JsSandbox&) = delete;

    /**
     * @brief Compile and run a JavaScript file.
     *
     * @param scriptPath Path to the input script.
     * @return Execution status, timeout flag, and diagnostic message.
     */
    ScriptResult executeFile(const std::string& scriptPath);

    /**
     * @brief Serialize the current V8 heap graph as JSON.
     *
     * @param path Output file path for the heap snapshot.
     * @throws std::runtime_error when the snapshot cannot be written.
     */
    void writeHeapSnapshot(const std::string& path);

    /**
     * @brief Return values pinned by mark(name, value).
     *
     * @return Immutable list of tracked values collected during execution.
     */
    const std::vector<TrackedValue>& trackedValues() const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};
