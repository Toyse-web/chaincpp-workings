// src/security/sandbox.cpp
#include "chaincpp/security/sandbox.hpp"

#ifdef _WIN32
    #include <windows.h>
    #include <processthreadsapi.h>
    #include <memoryapi.h>
    #include <jobapi2.h>
#else
    #include <sys/resource.h>
    #include <sys/time.h>
    #include <unistd.h>
    #include <signal.h>
    #include <setjmp.h>
#endif

#include <thread>
#include <atomic>
#include <cstring>

namespace chaincpp::security {

// Global timeout state
static std::atomic<bool> g_timeout_occurred{false};
static jmp_buf g_timeout_env;

#ifdef _WIN32
// Windows sandbox implementation
class WindowsSandbox {
public:
    static bool setMemoryLimit(size_t max_bytes) {
        HANDLE job = CreateJobObject(nullptr, nullptr);
        if (!job) return false;
        
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = {};
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_JOB_MEMORY;
        limits.JobMemoryLimit = max_bytes;
        
        return SetInformationJobObject(job, 
            JobObjectExtendedLimitInformation, &limits, sizeof(limits));
    }
    
    static bool setTimeout(std::chrono::milliseconds timeout) {
        // Windows uses waitable timers
        HANDLE timer = CreateWaitableTimer(nullptr, TRUE, nullptr);
        if (!timer) return false;
        
        LARGE_INTEGER due_time;
        due_time.QuadPart = -static_cast<LONGLONG>(timeout.count() * 10000);
        
        if (!SetWaitableTimer(timer, &due_time, 0, nullptr, nullptr, FALSE)) {
            return false;
        }
        
        // Timer will trigger via WaitForSingleObject
        return true;
    }
};
#endif

// Unix/POSIX sandbox implementation
#ifdef __unix__
class UnixSandbox {
public:
    static bool setMemoryLimit(size_t max_bytes) {
        struct rlimit limit;
        limit.rlim_cur = max_bytes;
        limit.rlim_max = max_bytes;
        return setrlimit(RLIMIT_AS, &limit) == 0;
    }
    
    static bool setCpuLimit(std::chrono::milliseconds timeout) {
        struct rlimit limit;
        limit.rlim_cur = timeout.count() / 1000;  // Convert to seconds
        limit.rlim_max = timeout.count() / 1000;
        return setrlimit(RLIMIT_CPU, &limit) == 0;
    }
    
    static void sanitizeEnvironment() {
        // Remove dangerous environment variables
        unsetenv("LD_PRELOAD");
        unsetenv("LD_LIBRARY_PATH");
        unsetenv("ORIGIN");
        unsetenv("BASH_ENV");
    }
};
#endif

Result<void> Sandbox::execute_safe(
    std::function<Result<void>()> func,
    const SecurityLimits& limits
) {
    // Reset timeout flag
    g_timeout_occurred = false;
    
    // Set resource limits
#ifdef __unix__
    if (!UnixSandbox::setMemoryLimit(limits.max_memory_bytes)) {
        return Result<void>::err("Failed to set memory limit");
    }
    
    if (!UnixSandbox::setCpuLimit(limits.timeout)) {
        return Result<void>::err("Failed to set CPU limit");
    }
    
    UnixSandbox::sanitizeEnvironment();
#elif defined(_WIN32)
    if (!WindowsSandbox::setMemoryLimit(limits.max_memory_bytes)) {
        return Result<void>::err("Failed to set memory limit");
    }
    
    if (!WindowsSandbox::setTimeout(limits.timeout)) {
        return Result<void>::err("Failed to set timeout");
    }
#endif
    
    // Execute with timeout protection
    std::atomic<bool> completed{false};
    std::string error_msg;
    
    std::thread worker([&]() {
        auto result = func();
        if (result.is_err()) {
            error_msg = result.error();
        }
        completed = true;
    });
    
    // Wait with timeout
    auto start = std::chrono::steady_clock::now();
    while (!completed) {
        auto now = std::chrono::steady_clock::now();
        if (now - start > limits.timeout) {
            g_timeout_occurred = true;
            worker.detach();  // Or terminate properly
            return Result<void>::err("Execution timeout exceeded");
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    
    worker.join();
    
    if (!error_msg.empty()) {
        return Result<void>::err(error_msg);
    }
    
    return Result<void>::ok();
}

} // namespace chaincpp::security
