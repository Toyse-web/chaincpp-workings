#pragma once

#include "sandbox.hpp"
#include <string>
#include <optional>
#include <vector>
#include <cstdint>

namespace chaincpp::security {

// Secure string that zeros memory on destruction
class secure_string {
public:
    secure_string() = default;
    explicit secure_string(const std::string& str);
    explicit secure_string(const char* str);
    ~secure_string();
    
    secure_string(const secure_string&) = delete;
    secure_string& operator=(const secure_string&) = delete;
    
    secure_string(secure_string&& other) noexcept;
    secure_string& operator=(secure_string&& other) noexcept;
    
    const char* c_str() const { return data_.get(); }
    size_t size() const { return size_; }
    bool empty() const { return size_ == 0; }
    
    std::string to_string() const;
    
private:
    void zero_memory();
    
    std::unique_ptr<char[], void(*)(void*)> data_{nullptr, [](void* p) {
        if (p) {
            volatile char* vp = static_cast<volatile char*>(p);
            for (size_t i = 0; i < 32; ++i) vp[i] = 0;
            free(p);
        }
    }};
    size_t size_ = 0;
};

// Manages API keys with encryption at rest
class SecretsManager {
public:
    static SecretsManager& instance();
    
    // Store a key (encrypted)
    Result<void> store_key(const std::string& service, const secure_string& key);
    
    // Retrieve a key
    Result<secure_string> get_key(const std::string& service);
    
    // Check if key exists
    bool has_key(const std::string& service) const;
    
    // Remove a key
    Result<void> remove_key(const std::string& service);
    
    // Load from environment variable
    Result<secure_string> load_from_env(const std::string& env_var);
    
private:
    SecretsManager() = default;
    
    // Platform-specific secure storage
    bool store_secure(const std::string& service, const std::vector<uint8_t>& encrypted);
    std::optional<std::vector<uint8_t>> retrieve_secure(const std::string& service);
    
    // Simple XOR encryption (obfuscation, not military grade)
    static std::vector<uint8_t> encrypt(const secure_string& plaintext);
    static secure_string decrypt(const std::vector<uint8_t>& ciphertext);
    
    // In-memory cache (cleared after use)
    struct CachedKey {
        secure_string key;
        std::chrono::steady_clock::time_point timestamp;
    };
    std::unordered_map<std::string, CachedKey> cache_;
    static constexpr auto CACHE_TTL = std::chrono::minutes(5);
    
    void cleanup_cache();
};

// RAII guard for temporarily using a key
class KeyGuard {
public:
    explicit KeyGuard(const std::string& service);
    ~KeyGuard();
    
    const secure_string* operator->() const { return &key_; }
    const secure_string& get() const { return key_; }
    bool valid() const { return valid_; }
    
private:
    secure_string key_;
    bool valid_ = false;
};

} // namespace chaincpp::security
