#pragma once

#include "tool.hpp"
#include "../models/llm.hpp"
#include "../core/prompt.hpp"
#include <memory>
#include <functional>

namespace chaincpp::agents {

// ============================================================================
// Agent Configuration
// ============================================================================

struct AgentConfig {
    size_t max_iterations = 10;
    std::chrono::seconds max_time{60};
    bool require_tool_approval = true;
    bool verbose = false;
    double temperature = 0.7;
    
    // Callbacks
    std::function<void(const std::string&)> on_thought = nullptr;
    std::function<void(const std::string&, const std::string&)> on_action = nullptr;
    std::function<void(const std::string&)> on_observation = nullptr;
    std::function<void(const std::string&)> on_final_answer = nullptr;
};

// ============================================================================
// ReAct Agent - Reason + Act loop
// ============================================================================

class ReActAgent {
public:
    static security::Result<std::unique_ptr<ReActAgent>> create(
        std::unique_ptr<models::BaseLLM> llm,
        std::vector<Tool> tools,
        AgentConfig config = {}
    );
    
    ~ReActAgent();
    
    // Run the agent on a user query
    security::Result<std::string> run(const std::string& user_input);
    
    // Get conversation history
    std::vector<std::string> get_conversation_history() const;
    
    // Add system prompt override
    void set_system_prompt(const std::string& prompt);
    
private:
    ReActAgent() = default;
    
    class Impl;
    std::unique_ptr<Impl> impl_;
};

// ============================================================================
// Simple Agent (no tools)
// ============================================================================

class SimpleAgent {
public:
    static security::Result<std::unique_ptr<SimpleAgent>> create(
        std::unique_ptr<models::BaseLLM> llm,
        AgentConfig config = {}
    );
    
    ~SimpleAgent();
    
    security::Result<std::string> chat(const std::string& user_input);
    
private:
    SimpleAgent() = default;
    
    class Impl;
    std::unique_ptr<Impl> impl_;
};

// ============================================================================
// Conversation Memory
// ============================================================================

class ConversationMemory {
public:
    void add_user_message(const std::string& message);
    void add_assistant_message(const std::string& message);
    void add_system_message(const std::string& message);
    
    std::vector<models::Message> get_messages(size_t limit = 0) const;
    void clear();
    void set_max_history(size_t max) { max_history_ = max; }
    
private:
    std::vector<models::Message> messages_;
    size_t max_history_ = 50;
};

} // namespace chaincpp::agents
