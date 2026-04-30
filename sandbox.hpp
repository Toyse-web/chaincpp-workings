// include/chaincpp/security/sandbox.hpp
#pragma once

#include <chrono>
#include <functional>
#include <string>
#include <system_error>

namespace chaincpp::security {

// Forward declaration
class Sandbox;

// Result type for error handling (no exceptions for security)
template<typename T>
class Result {
public:
    static Result<T> ok(T value) {
        Result r;
        r.value_ = std::move(value);
        r.has_value_ = true;
        return r;
    }
    
    static Result<T> err(std::string error) {
        Result r;
        r.error_ = std::move(error);
        r.has_value_ = false;
        return r;
    }
    
    bool is_ok() const { return has_value_; }
    bool is_err() const { return !has_value_; }
    
    T& value() { 
        if (!has_value_) throw std::runtime_error(error_);
        return value_; 
    }
    
    std::string error() const { return error_; }
    
private:
    T value_;
    std::string error_;
    bool has_value_ = false;
};

// Specialize for void
template<>
class Result<void> {
public:
    static Result<void> ok() {
        Result r;
        r.has_value_ = true;
        return r;
    }
    
    static Result<void> err(std::string error) {
        Result r;
        r.error_ = std::move(error);
        r.has_value_ = false;
        return r;
    }
    
    bool is_ok() const { return has_value_; }
    bool is_err() const { return !has_value_; }
    std::string error() const { return error_; }
    
private:
    std::string error_;
    bool has_value_ = false;
};

// Security limits for sandboxed execution
struct SecurityLimits {
    std::chrono::milliseconds timeout{5000};  // 5 seconds max
    size_t max_memory_bytes{100 * 1024 * 1024};  // 100MB max
    size_t max_output_bytes{1024 * 1024};  // 1MB output limit
    bool allow_network{false};
    bool allow_filesystem{false};
    
    // Factory for safe defaults
    static SecurityLimits safe_defaults() {
        return SecurityLimits{};
    }
    
    // Stricter for user code
    static SecurityLimits strict() {
        auto limits = SecurityLimits{};
        limits.timeout = std::chrono::seconds(1);
        limits.max_memory_bytes = 10 * 1024 * 1024;  // 10MB
        limits.max_output_bytes = 100 * 1024;  // 100KB
        return limits;
    }
};

// Main sandbox class
class Sandbox {
public:
    // Execute a function with security restrictions
    static Result<void> execute_safe(
        std::function<Result<void>()> func,
        const SecurityLimits& limits = SecurityLimits::safe_defaults()
    );
    
    // For functions that return a value
    template<typename T>
    static Result<T> execute_safe_result(
        std::function<Result<T>()> func,
        const SecurityLimits& limits = SecurityLimits::safe_defaults()
    );
    
private:
    // Platform-specific implementation
    static bool set_memory_limit(size_t max_bytes);
    static bool set_timeout(std::chrono::milliseconds timeout);
    static void sanitize_environment();
};

} // namespace chaincpp::security
