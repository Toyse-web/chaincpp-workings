// examples/basic_usage.cpp
#include "chaincpp/security/sandbox.hpp"
#include <iostream>

using namespace chaincpp::security;

int main() {
    std::cout << "chaincpp - Secure LLM Library Demo\n";
    std::cout << "==================================\n\n";
    
    // Create a safe tool execution
    auto safe_operation = []() -> Result<void> {
        std::cout << "Executing tool safely...\n";
        // Your tool logic here
        return Result<void>::ok();
    };
    
    // Run with security limits
    auto result = Sandbox::execute_safe(safe_operation);
    
    if (result.is_ok()) {
        std::cout << "✓ Tool executed safely\n";
    } else {
        std::cout << "✗ Tool failed: " << result.error() << "\n";
    }
    
    // Example of blocked operation
    std::cout << "\nTesting malicious code detection...\n";
    auto bad_operation = []() -> Result<void> {
        // In real code, this would try system calls
        // system("rm -rf /");  // Would be blocked by sandbox
        
        std::cout << " (attempted malicious operation would be blocked)\n";
        return Result<void>::ok();
    };
    
    auto bad_result = Sandbox::execute_safe(bad_operation, SecurityLimits::strict());
    
    if (bad_result.is_ok()) {
        std::cout << "Operation completed (sandbox prevented actual damage)\n";
    }
    
    return 0;
}
