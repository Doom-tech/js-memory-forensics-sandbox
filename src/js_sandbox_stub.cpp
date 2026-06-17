#include "js_sandbox.hpp"

#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

std::string unavailableMessage() {
    return "V8 support was not compiled in. Install V8 development libraries "
           "or configure with -DJSFS_REQUIRE_V8=ON to make this a hard error.";
}

} // namespace

class V8Runtime::Impl {
public:
    Impl(const char* executablePath, int maxOldSpaceMb) {
        (void)executablePath;
        (void)maxOldSpaceMb;
        throw std::runtime_error(unavailableMessage());
    }
};

class JsSandbox::Impl {
public:
    explicit Impl(SandboxConfig config) {
        (void)config;
        throw std::runtime_error(unavailableMessage());
    }

    ScriptResult executeFile(const std::string& scriptPath) {
        (void)scriptPath;
        throw std::runtime_error(unavailableMessage());
    }

    void writeHeapSnapshot(const std::string& path) {
        (void)path;
        throw std::runtime_error(unavailableMessage());
    }

    const std::vector<TrackedValue>& trackedValues() const {
        return tracked_;
    }

private:
    std::vector<TrackedValue> tracked_;
};

V8Runtime::V8Runtime(const char* executablePath, int maxOldSpaceMb)
    : impl_(std::make_unique<Impl>(executablePath, maxOldSpaceMb)) {}

V8Runtime::~V8Runtime() = default;

JsSandbox::JsSandbox(SandboxConfig config) : impl_(std::make_unique<Impl>(config)) {}

JsSandbox::~JsSandbox() = default;

ScriptResult JsSandbox::executeFile(const std::string& scriptPath) {
    return impl_->executeFile(scriptPath);
}

void JsSandbox::writeHeapSnapshot(const std::string& path) {
    impl_->writeHeapSnapshot(path);
}

const std::vector<TrackedValue>& JsSandbox::trackedValues() const {
    return impl_->trackedValues();
}
