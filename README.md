# chaincpp
A C++ library for LangChain

# chaincpp - Secure C++ LLM Library

**chaincpp** is a security-first C++ library for building LLM applications, similar to Python's LangChain but with native C++ performance and built-in sandboxing.

## Current Status: Phase 0 - Security Foundation

The sandbox system is complete and production-ready.

## Features

- **Secure sandbox** with resource limits (CPU time, memory)
- **Platform support** (Windows, Linux, macOS)
- **Result type** for safe error handling (no exceptions)
- **Timeout protection** against infinite loops
- **Memory limit enforcement**
- **Environment sanitization**
- **Test suite** with security validation

## Quick Start

### Build

```bash
mkdir build && cd build
cmake ..
cmake --build .
