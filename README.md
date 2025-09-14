# SPUUF
**Note: A x64 reverse shell payload is baked in with IP:PORT 127.0.0.1:7777 for testing!**

## Overview

SPUUF demonstrates sophisticated evasion techniques that manipulate call stacks to evade behavioral analysis systems. It creates synthetic call frames, spoofs return addresses during syscalls, and uses indirect execution to obscure memory operations from security products.

## Key Features

- **Dynamic API Resolution** - PEB walking with checksum-based function resolution
- **Return Address Spoofing** - Manipulates stack during NT API calls
- **Synthetic Call Stack Generation** - Creates legitimate-looking call histories
- **Thread Context Manipulation** - Injects fake stack frames into suspended threads
- **Indirect Execution** - JIT compilation with trampoline-based execution
- **Behavioral Evasion** - Disguises memory operations as legitimate Windows operations

## Technical Details

The PoC implements several evasion layers:

1. **API Hiding**: Manual resolution via PEB/LDR traversal avoiding IAT
2. **Stack Spoofing**: Return addresses point to benign Windows functions during syscalls
3. **Fake Call Stacks**: Constructs realistic frames using UNWIND_INFO parsing
4. **Execution Obfuscation**: Multi-stage execution through worker threads and JIT

## Effectiveness

Designed to evade:
- Call stack analysis
- Behavioral pattern detection  
- API monitoring
- Basic EDR stack walking
- User-mode hooks

## Usage

```bash
# Compile with Visual Studio (x64 Release)
cl.exe /O2 /MT spuuf_v3.cpp

# Run (will execute embedded payload)
spuuf_v3.exe
```

## Disclaimer

**IMPORTANT: This project is for educational and authorized security research purposes only.**

- **DO NOT** use this code for malicious purposes
- **DO NOT** use this code on systems you don't own or lack authorization to test
- **DO NOT** use this code to bypass security products in production environments
- This code is provided "as-is" without warranties
- The author assumes no responsibility for misuse of this code

## License

MIT License - See LICENSE file for details
