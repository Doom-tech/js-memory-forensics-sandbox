#include "js_sandbox.hpp"

#include "base64.hpp"

#include <libplatform/libplatform.h>
#include <v8-profiler.h>
#include <v8.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <memory>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <thread>

namespace {

std::string readTextFile(const std::string& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        throw std::runtime_error("cannot open script: " + path);
    }

    std::ostringstream buffer;
    buffer << input.rdbuf();
    return buffer.str();
}

class FileOutputStream final : public v8::OutputStream {
public:
    explicit FileOutputStream(std::ofstream& out) : out_(out) {}

    WriteResult WriteAsciiChunk(char* data, int size) override {
        out_.write(data, size);
        return out_ ? kContinue : kAbort;
    }

    void EndOfStream() override {
        out_.flush();
    }

private:
    std::ofstream& out_;
};

} // namespace

class V8Runtime::Impl {
public:
    Impl(const char* executablePath, int maxOldSpaceMb) {
        if (maxOldSpaceMb <= 0) {
            throw std::runtime_error("V8 old-space limit must be positive");
        }

        std::string flags = "--max-old-space-size=" + std::to_string(maxOldSpaceMb);
        v8::V8::SetFlagsFromString(flags.c_str(), static_cast<int>(flags.size()));

        v8::V8::InitializeICUDefaultLocation(executablePath);
        v8::V8::InitializeExternalStartupData(executablePath);

        platform_ = v8::platform::NewDefaultPlatform();
        v8::V8::InitializePlatform(platform_.get());
        v8::V8::Initialize();
    }

    ~Impl() {
        v8::V8::Dispose();
        v8::V8::DisposePlatform();
    }

private:
    std::unique_ptr<v8::Platform> platform_;
};

class JsSandbox::Impl {
public:
    explicit Impl(SandboxConfig config) : config_(config) {
        if (config_.timeoutMs <= 0) {
            throw std::runtime_error("timeout must be positive");
        }
        if (config_.maxOldSpaceMb <= 0) {
            throw std::runtime_error("V8 old-space limit must be positive");
        }

        allocator_.reset(v8::ArrayBuffer::Allocator::NewDefaultAllocator());

        v8::Isolate::CreateParams params;
        params.array_buffer_allocator = allocator_.get();
        params.constraints.ConfigureDefaultsFromHeapSize(
            0,
            static_cast<size_t>(config_.maxOldSpaceMb) * 1024U * 1024U
        );

        isolate_ = v8::Isolate::New(params);
        if (isolate_ == nullptr) {
            throw std::runtime_error("cannot create V8 isolate");
        }

        createContext();
    }

    ~Impl() {
        context_.Reset();
        pinnedValues_.clear();

        if (isolate_ != nullptr) {
            isolate_->Dispose();
            isolate_ = nullptr;
        }
    }

    ScriptResult executeFile(const std::string& scriptPath) {
        const std::string sourceText = readTextFile(scriptPath);

        std::atomic<bool> timedOut(false);
        std::mutex mutex;
        std::condition_variable done;
        bool finished = false;

        std::thread watchdog([&]() {
            std::unique_lock<std::mutex> lock(mutex);
            const bool finishedInTime = done.wait_for(
                lock,
                std::chrono::milliseconds(config_.timeoutMs),
                [&]() { return finished; }
            );

            if (!finishedInTime) {
                timedOut.store(true);
                isolate_->TerminateExecution();
            }
        });

        auto stopWatchdog = [&]() {
            {
                std::lock_guard<std::mutex> lock(mutex);
                finished = true;
            }
            done.notify_one();
            if (watchdog.joinable()) {
                watchdog.join();
            }
        };

        ScriptResult result;

        try {
            v8::Locker locker(isolate_);
            v8::Isolate::Scope isolateScope(isolate_);
            v8::HandleScope handleScope(isolate_);
            v8::Local<v8::Context> context = context_.Get(isolate_);
            v8::Context::Scope contextScope(context);
            v8::TryCatch tryCatch(isolate_);

            v8::Local<v8::String> source;
            if (!v8::String::NewFromUtf8(
                    isolate_,
                    sourceText.c_str(),
                    v8::NewStringType::kNormal,
                    static_cast<int>(sourceText.size())
                ).ToLocal(&source)) {
                throw std::runtime_error("cannot allocate JS source string");
            } else {
                runCompiledScript(context, source, tryCatch, result);
            }
        } catch (...) {
            stopWatchdog();
            throw;
        }

        stopWatchdog();

        result.timedOut = timedOut.load();
        if (result.timedOut) {
            result.ok = false;
            result.message = "script was stopped by timeout";
            isolate_->CancelTerminateExecution();
        }

        return result;
    }

    void writeHeapSnapshot(const std::string& path) {
        std::ofstream out(path, std::ios::binary);
        if (!out) {
            throw std::runtime_error("cannot create heap snapshot file: " + path);
        }

        v8::Locker locker(isolate_);
        v8::Isolate::Scope isolateScope(isolate_);
        v8::HandleScope handleScope(isolate_);
        v8::Local<v8::Context> context = context_.Get(isolate_);
        v8::Context::Scope contextScope(context);

        const v8::HeapSnapshot* snapshot = isolate_->GetHeapProfiler()->TakeHeapSnapshot();
        if (snapshot == nullptr) {
            throw std::runtime_error("V8 did not return a heap snapshot");
        }

        FileOutputStream stream(out);
        snapshot->Serialize(&stream, v8::HeapSnapshot::kJSON);
        const_cast<v8::HeapSnapshot*>(snapshot)->Delete();

        if (!out) {
            throw std::runtime_error("heap snapshot write failed: " + path);
        }
    }

    const std::vector<TrackedValue>& trackedValues() const {
        return tracked_;
    }

private:
    void runCompiledScript(
        v8::Local<v8::Context> context,
        v8::Local<v8::String> source,
        v8::TryCatch& tryCatch,
        ScriptResult& result
    ) {
        v8::Local<v8::Script> script;
        if (!v8::Script::Compile(context, source).ToLocal(&script)) {
            result.message = formatException(tryCatch);
            return;
        }

        v8::Local<v8::Value> value;
        if (!script->Run(context).ToLocal(&value)) {
            result.message = formatException(tryCatch);
            return;
        }

        result.ok = true;
        result.message = "script finished normally";
    }

    void createContext() {
        v8::Locker locker(isolate_);
        v8::Isolate::Scope isolateScope(isolate_);
        v8::HandleScope handleScope(isolate_);

        v8::Local<v8::ObjectTemplate> global = v8::ObjectTemplate::New(isolate_);
        v8::Local<v8::External> self =
            v8::External::New(isolate_, this, v8::kExternalPointerTypeTagDefault);

        global->Set(
            v8::String::NewFromUtf8Literal(isolate_, "print"),
            v8::FunctionTemplate::New(isolate_, &JsSandbox::Impl::printCallback, self)
        );
        global->Set(
            v8::String::NewFromUtf8Literal(isolate_, "mark"),
            v8::FunctionTemplate::New(isolate_, &JsSandbox::Impl::markCallback, self)
        );
        global->Set(
            v8::String::NewFromUtf8Literal(isolate_, "atob"),
            v8::FunctionTemplate::New(isolate_, &JsSandbox::Impl::atobCallback, self)
        );

        v8::Local<v8::Context> context = v8::Context::New(isolate_, nullptr, global);
        context_.Reset(isolate_, context);
    }

    static void printCallback(const v8::FunctionCallbackInfo<v8::Value>& args) {
        v8::Isolate* isolate = args.GetIsolate();

        for (int i = 0; i < args.Length(); ++i) {
            if (i != 0) {
                std::cout << ' ';
            }
            std::cout << toUtf8(isolate, args[i]);
        }
        std::cout << '\n';
    }

    static void markCallback(const v8::FunctionCallbackInfo<v8::Value>& args) {
        if (args.Length() < 2) {
            return;
        }

        v8::Isolate* isolate = args.GetIsolate();
        auto* self = static_cast<JsSandbox::Impl*>(
            v8::Local<v8::External>::Cast(args.Data())->Value(v8::kExternalPointerTypeTagDefault)
        );

        TrackedValue item;
        item.name = toUtf8(isolate, args[0]);
        item.preview = toUtf8(isolate, args[1]);

        if (args[1]->IsObject()) {
            item.identityHash = args[1].As<v8::Object>()->GetIdentityHash();
        }

        self->tracked_.push_back(item);
        self->pinnedValues_.emplace_back(isolate, args[1]);
    }

    static void atobCallback(const v8::FunctionCallbackInfo<v8::Value>& args) {
        v8::Isolate* isolate = args.GetIsolate();
        if (args.Length() < 1) {
            isolate->ThrowException(v8::Exception::TypeError(
                v8::String::NewFromUtf8Literal(isolate, "atob expects one argument")
            ));
            return;
        }

        try {
            const std::string encoded = toUtf8(isolate, args[0]);
            const std::string decoded = decodeBase64Strict(encoded);
            v8::Local<v8::String> value;
            const auto* decodedBytes =
                reinterpret_cast<const std::uint8_t*>(decoded.data());
            if (!v8::String::NewFromOneByte(
                    isolate,
                    decodedBytes,
                    v8::NewStringType::kNormal,
                    static_cast<int>(decoded.size())
                ).ToLocal(&value)) {
                isolate->ThrowException(v8::Exception::Error(
                    v8::String::NewFromUtf8Literal(isolate, "cannot allocate atob result")
                ));
                return;
            }
            args.GetReturnValue().Set(value);
        } catch (const std::exception& error) {
            v8::Local<v8::String> message;
            if (!v8::String::NewFromUtf8(
                    isolate,
                    error.what(),
                    v8::NewStringType::kNormal
                ).ToLocal(&message)) {
                message = v8::String::NewFromUtf8Literal(isolate, "atob failed");
            }
            isolate->ThrowException(v8::Exception::Error(
                message
            ));
        }
    }

    std::string formatException(v8::TryCatch& tryCatch) {
        std::ostringstream out;
        out << toUtf8(isolate_, tryCatch.Exception());

        v8::Local<v8::Message> message = tryCatch.Message();
        if (!message.IsEmpty()) {
            v8::Local<v8::Context> context = context_.Get(isolate_);
            const int line = message->GetLineNumber(context).FromMaybe(0);
            out << " at line " << line;
        }

        return out.str();
    }

    static std::string toUtf8(v8::Isolate* isolate, v8::Local<v8::Value> value) {
        if (value.IsEmpty()) {
            return "<empty>";
        }

        v8::Local<v8::Context> context = isolate->GetCurrentContext();
        v8::Local<v8::String> text;
        if (!value->ToString(context).ToLocal(&text)) {
            return "<not printable>";
        }

        v8::String::Utf8Value utf8(isolate, text);
        if (*utf8 == nullptr) {
            return "<utf8 conversion failed>";
        }

        return std::string(*utf8, static_cast<size_t>(utf8.length()));
    }

private:
    SandboxConfig config_;
    v8::Isolate* isolate_ = nullptr;
    std::unique_ptr<v8::ArrayBuffer::Allocator> allocator_;
    v8::Global<v8::Context> context_;
    std::vector<v8::Global<v8::Value>> pinnedValues_;
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
