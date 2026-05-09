#pragma once

#include "../security/sandbox.hpp"
#include "../security/secrets.hpp"
#include "../core/prompt.hpp"
#include <string>
#include <vector>
#include <functional>
#include <memory>

namespace chaincpp::models {

// Message types for chat
struct Message {
    enum class Role {
        SYSTEM,
        USER,
        ASSISTANT,
        TOOL
    };
    
    Role role;
    std::string content;
    std::string name;  // Optional, for tool messages
    
    static Message system(std::string content);
    static Message user(std::string content);
    static Message assistant(std::string content);
    static Message tool(std::string content, std::string name);
};

// Streaming callback
using StreamCallback = std::function<security::Result<void>(std::string_view chunk)>;

// Model configuration
struct ModelConfig {
    std::string model_name = "gpt-3.5-turbo";
    double temperature = 0.7;
    double top_p = 1.0;
    int max_tokens = 1000;
    std::chrono::seconds timeout{30};
    size_t max_retries = 3;
    bool verify_tls = true;
    
    // Rate limiting
    size_t requests_per_minute = 60;
    size_t tokens_per_minute = 100000;
};

// Base LLM interface
class BaseLLM {
public:
    virtual ~BaseLLM() = default;
    
    // Generate response
    virtual security::Result<std::string> generate(
        const std::vector<Message>& messages,
        const ModelConfig& config = ModelConfig{}
    ) = 0;
    
    // Stream response
    virtual security::Result<void> stream_generate(
        const std::vector<Message>& messages,
        StreamCallback on_chunk,
        const ModelConfig& config = ModelConfig{}
    ) = 0;
    
    // Count tokens (approximate)
    virtual size_t count_tokens(const std::string& text) const = 0;
};

// ============================================================================
// OpenAI Implementation
// ============================================================================

class OpenAIChat : public BaseLLM {
public:
    struct Config {
        std::string api_key_env_var = "OPENAI_API_KEY";
        std::string base_url = "https://api.openai.com/v1";
        std::string organization;  // Optional org ID
    };
    
    static security::Result<std::unique_ptr<OpenAIChat>> create(Config cfg = {});
    ~OpenAIChat();
    
    security::Result<std::string> generate(
        const std::vector<Message>& messages,
        const ModelConfig& config = ModelConfig{}
    ) override;
    
    security::Result<void> stream_generate(
        const std::vector<Message>& messages,
        StreamCallback on_chunk,
        const ModelConfig& config = ModelConfig{}
    ) override;
    
    size_t count_tokens(const std::string& text) const override;
    
private:
    OpenAIChat() = default;
    
    security::secure_string api_key_;
    Config config_;
    
    security::Result<std::string> make_request(
        const std::vector<Message>& messages,
        const ModelConfig& config,
        StreamCallback on_chunk = nullptr
    );
};

// ============================================================================
// Anthropic Implementation
// ============================================================================

class AnthropicChat : public BaseLLM {
public:
    struct Config {
        std::string api_key_env_var = "ANTHROPIC_API_KEY";
        std::string base_url = "https://api.anthropic.com/v1";
        std::string version = "2023-06-01";
    };
    
    static security::Result<std::unique_ptr<AnthropicChat>> create(Config cfg = {});
    ~AnthropicChat();
    
    security::Result<std::string> generate(
        const std::vector<Message>& messages,
        const ModelConfig& config = ModelConfig{}
    ) override;
    
    security::Result<void> stream_generate(
        const std::vector<Message>& messages,
        StreamCallback on_chunk,
        const ModelConfig& config = ModelConfig{}
    ) override;
    
    size_t count_tokens(const std::string& text) const override;
    
private:
    AnthropicChat() = default;
    
    security::secure_string api_key_;
    Config config_;
};

// ============================================================================
// Local LLM (llama.cpp integration)
// ============================================================================

class LocalLLM : public BaseLLM {
public:
    struct Config {
        std::string model_path;
        size_t context_size = 4096;
        int gpu_layers = 0;  // Number of layers to offload to GPU
        bool use_mmap = true;
        bool use_mlock = false;
        
        // Security limits
        security::SecurityLimits limits = security::SecurityLimits::strict();
    };
    
    static security::Result<std::unique_ptr<LocalLLM>> create(Config cfg);
    ~LocalLLM();
    
    security::Result<std::string> generate(
        const std::vector<Message>& messages,
        const ModelConfig& config = ModelConfig{}
    ) override;
    
    security::Result<void> stream_generate(
        const std::vector<Message>& messages,
        StreamCallback on_chunk,
        const ModelConfig& config = ModelConfig{}
    ) override;
    
    size_t count_tokens(const std::string& text) const override;
    
private:
    LocalLLM() = default;
    
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace chaincpp::models
