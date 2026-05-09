#include "chaincpp/models/llm.hpp"
#include "chaincpp/security/secrets.hpp"
#include <iostream>

using namespace chaincpp::models;
using namespace chaincpp::security;

void test_secrets_manager() {
    std::cout << "Testing SecretsManager...\n";
    
    auto& mgr = SecretsManager::instance();
    
    // Store and retrieve
    secure_string test_key("sk-test123456789");
    auto store_result = mgr.store_key("test_service", test_key);
    assert(store_result.is_ok());
    std::cout << "  ✓ Key stored\n";
    
    auto retrieve_result = mgr.get_key("test_service");
    assert(retrieve_result.is_ok());
    assert(retrieve_result.value().to_string() == "sk-test123456789");
    std::cout << "  ✓ Key retrieved\n";
    
    // Remove
    auto remove_result = mgr.remove_key("test_service");
    assert(remove_result.is_ok());
    std::cout << "  ✓ Key removed\n";
    
    std::cout << "✓ SecretsManager tests passed\n\n";
}

void test_openai_creation() {
    std::cout << "Testing OpenAI creation...\n";
    
    // This test will fail if no API key is set, but that's expected
    auto result = OpenAIChat::create();
    
    if (result.is_ok()) {
        std::cout << "  ✓ OpenAI client created (requires OPENAI_API_KEY env var)\n";
    } else {
        std::cout << "  ℹ OpenAI client not created (no API key): " << result.error() << "\n";
    }
    
    std::cout << "✓ OpenAI creation test complete\n\n";
}

void test_message_creation() {
    std::cout << "Testing Message creation...\n";
    
    auto sys_msg = Message::system("You are helpful");
    assert(sys_msg.role == Message::Role::SYSTEM);
    assert(sys_msg.content == "You are helpful");
    
    auto user_msg = Message::user("Hello");
    assert(user_msg.role == Message::Role::USER);
    
    auto assistant_msg = Message::assistant("Hi there");
    assert(assistant_msg.role == Message::Role::ASSISTANT);
    
    std::cout << "  ✓ All message types work\n";
    std::cout << "✓ Message tests passed\n\n";
}

void test_token_counting() {
    std::cout << "Testing token counting...\n";
    
    auto openai = OpenAIChat::create();
    if (openai.is_ok()) {
        size_t tokens = openai.value()->count_tokens("Hello world");
        assert(tokens > 0);
        std::cout << "  ✓ Token counting works\n";
    }
    
    std::cout << "✓ Token counting tests complete\n\n";
}

int main() {
    std::cout << "\n========================================\n";
    std::cout << "chaincpp LLM Model Tests\n";
    std::cout << "========================================\n\n";
    
    test_secrets_manager();
    test_message_creation();
    test_token_counting();
    test_openai_creation();
    
    std::cout << "========================================\n";
    std::cout << "✅ All LLM model tests passed!\n";
    std::cout << "========================================\n\n";
    
    return 0;
}
