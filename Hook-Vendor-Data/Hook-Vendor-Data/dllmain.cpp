#include <Windows.h>
#include <psapi.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <fstream>
#include <locale>
#include <codecvt>
#include <mutex>
#include <vector>
#include <cstdlib>
#include "MinHook.h"

#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "libMinHook.x64.lib")

constexpr uintptr_t GETCURRENTVENDOR_RVA = 0x12D9340;
constexpr uintptr_t GETCURRENTVENDOR_ABSOLUTE = 0x1812D9340;

using GetCurrentVendorEnvDataFunc = void* (__fastcall*)(void* /*unused*/);
GetCurrentVendorEnvDataFunc originalGetCurrentVendor = nullptr;

bool hooksInstalled = false;
uintptr_t g_GetCurrentVendorAddr = 0;
extern "C" __declspec(dllexport) uintptr_t g_HookAddressVar = 0;

struct Il2CppString
{
    void* klass;
    void* monitor;
    int32_t length;
    wchar_t chars[1];
};

struct Il2CppArray
{
    void* klass;
    void* monitor;
    void* bounds;
    uintptr_t max_length;
    uint8_t vector[1];
};

std::mutex fileMutex;

std::string WideToUTF8(const std::wstring& wstr)
{
    if (wstr.empty()) return "";
    int utf8Size = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.length(), nullptr, 0, nullptr, nullptr);
    if (utf8Size <= 0) return "";
    std::string result(utf8Size, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.length(), &result[0], utf8Size, nullptr, nullptr);
    return result;
}

std::wstring GetStringFromIl2CppString(void* il2cppStr)
{
    if (!il2cppStr) return L"(null)";
    try
    {
        Il2CppString* str = reinterpret_cast<Il2CppString*>(il2cppStr);
        if (IsBadReadPtr(str, sizeof(Il2CppString)))
            return L"(invalid_ptr)";
        int32_t length = str->length;
        if (length < 0 || length > 100000)
            return L"(invalid_length)";
        std::wstring result;
        result.reserve(length);
        for (int32_t i = 0; i < length; i++)
        {
            if (IsBadReadPtr(&str->chars[i], sizeof(wchar_t)))
                result += L'?';
            else
                result += str->chars[i];
        }
        return result;
    }
    catch (...)
    {
        return L"(exception)";
    }
}

void* ReadPointerField(void* obj, size_t offset)
{
    if (!obj) return nullptr;
    void* addr = (void*)((uintptr_t)obj + offset);
    if (IsBadReadPtr(addr, sizeof(void*)))
        return nullptr;
    void* val = nullptr;
    memcpy(&val, addr, sizeof(void*));
    return val;
}

int32_t ReadInt32Field(void* obj, size_t offset)
{
    if (!obj) return 0;
    void* addr = (void*)((uintptr_t)obj + offset);
    if (IsBadReadPtr(addr, sizeof(int32_t)))
        return 0;
    int32_t v = 0;
    memcpy(&v, addr, sizeof(int32_t));
    return v;
}

std::string ReadStringFieldUtf8(void* obj, size_t offset)
{
    void* strPtr = ReadPointerField(obj, offset);
    if (!strPtr) return "";
    std::wstring w = GetStringFromIl2CppString(strPtr);
    return WideToUTF8(w);
}

std::string ReadStringArrayFieldUtf8(void* obj, size_t offset)
{
    void* arrPtr = ReadPointerField(obj, offset);
    if (!arrPtr) return "[]";
    Il2CppArray* arr = reinterpret_cast<Il2CppArray*>(arrPtr);
    if (IsBadReadPtr(arr, sizeof(Il2CppArray)))
        return "[]";
    uintptr_t len = arr->max_length;
    if (len == 0) return "[]";
    if (len > 10000) return "[]";
    std::string result = "[";
    void** elems = reinterpret_cast<void**>(arr->vector);
    for (uintptr_t i = 0; i < len; i++)
    {
        if (IsBadReadPtr(&elems[i], sizeof(void*)))
        {
            result += "\"(invalid)\"";
        }
        else
        {
            void* elem = elems[i];
            std::wstring w = GetStringFromIl2CppString(elem);
            std::string s = WideToUTF8(w);
            for (auto& c : s) if (c == '"') c = '\'';
            result += "\"" + s + "\"";
        }
        if (i + 1 < len) result += ",";
    }
    result += "]";
    return result;
}

std::string VendorEnvDataToJsonString(void* vendorObj)
{
    if (!vendorObj) return "null";
    std::string content = "{\n";
    auto safeAdd = [&](const std::string& key, const std::string& val, bool quote = true) {
        std::string v = val;
        for (auto& c : v) if (c == '"') c = '\'';
        if (quote)
            content += "    \"" + key + "\": \"" + v + "\",\n";
        else
            content += "    \"" + key + "\": " + v + ",\n";
        };
    safeAdd("name", ReadStringFieldUtf8(vendorObj, 0x10));
    safeAdd("vendorDisplayName", ReadStringFieldUtf8(vendorObj, 0x18));
    int32_t flags = ReadInt32Field(vendorObj, 0x20);
    safeAdd("flags", std::to_string(flags), false);
    safeAdd("clientVersion_Android", ReadStringFieldUtf8(vendorObj, 0x28));
    safeAdd("clientVersion_IOS", ReadStringFieldUtf8(vendorObj, 0x30));
    safeAdd("clientVersion_Windows", ReadStringFieldUtf8(vendorObj, 0x38));
    int32_t timezone = ReadInt32Field(vendorObj, 0x40);
    safeAdd("timeZone", std::to_string(timezone), false);
    safeAdd("localLanguage", ReadStringFieldUtf8(vendorObj, 0x48));
    safeAdd("voiceLanguage", ReadStringFieldUtf8(vendorObj, 0x50));
    std::string txtArr = ReadStringArrayFieldUtf8(vendorObj, 0x58);
    content += "    \"availableTextLanguages\": " + txtArr + ",\n";
    std::string voArr = ReadStringArrayFieldUtf8(vendorObj, 0x60);
    content += "    \"availableVoiceLanguages\": " + voArr + ",\n";
    safeAdd("sdkName", ReadStringFieldUtf8(vendorObj, 0x68));
    safeAdd("serverURL", ReadStringFieldUtf8(vendorObj, 0x70));
    safeAdd("serverChannelName", ReadStringFieldUtf8(vendorObj, 0x78));
    safeAdd("serverMetaKey", ReadStringFieldUtf8(vendorObj, 0x80));
    safeAdd("reviewServerMetaKey", ReadStringFieldUtf8(vendorObj, 0x88));
    safeAdd("serverGarbleKey", ReadStringFieldUtf8(vendorObj, 0x90));
    safeAdd("reviewServerGarbleKey", ReadStringFieldUtf8(vendorObj, 0x98));
    if (!content.empty()) {
        if (content.back() == '\n') content.pop_back();
        if (content.back() == ',') content.pop_back();
    }
    content += "\n}";
    return content;
}

void SaveVendorEnvDataToFile(void* vendorObj, const std::string& outFile)
{
    try
    {
        std::string content = VendorEnvDataToJsonString(vendorObj);
        std::lock_guard<std::mutex> lock(fileMutex);
        std::ofstream f(outFile, std::ios::out | std::ios::trunc | std::ios::binary);
        if (f.is_open())
        {
            unsigned char bom[] = { 0xEF, 0xBB, 0xBF };
            f.write(reinterpret_cast<const char*>(bom), sizeof(bom));
            f.write(content.c_str(), content.size());
            f.flush();
            f.close();
        }
    }
    catch (...)
    {
        printf("[*] Exception occurred while saving VendorEnvData to file\n");
    }
}

void* __fastcall HookedGetCurrentVendorEnvData(void* unused)
{
    void* result = nullptr;
    if (originalGetCurrentVendor)
    {
        result = originalGetCurrentVendor(unused);
    }
    SaveVendorEnvDataToFile(result, "CurrentVendorEnvData.json");
	printf("[*] GetCurrentVendorEnvData called, data saved to CurrentVendorEnvData.json\n");
    return result;
}

uintptr_t CalculateFunctionAddress(HMODULE module, uintptr_t rvaOffset)
{
    if (!module) return 0;
    uintptr_t baseAddress = (uintptr_t)module;
    uintptr_t functionAddress = baseAddress + rvaOffset;
    if (IsBadReadPtr((void*)functionAddress, 4))
        return 0;
    return functionAddress;
}

bool InstallHooks()
{
    printf("[+] Try installing hook...\n");

    const char* possibleModuleNames[] = {
        "GameAssembly.dll",
        "UnityPlayer.dll",
        "mono.dll",
        nullptr
    };

    HMODULE targetModule = nullptr;
    for (int i = 0; possibleModuleNames[i] != nullptr; i++)
    {
        targetModule = GetModuleHandleA(possibleModuleNames[i]);
        if (targetModule)
            break;
    }

    if (!targetModule)
    {
        printf("[+] Waiting for GameAssembly.dll module to load...\n");
        printf("========================================\n");

        int attempts = 0;
        const int maxAttempts = 200;

        while (!targetModule && attempts < maxAttempts)
        {
            targetModule = GetModuleHandleA("GameAssembly.dll");
            if (!targetModule)
            {
                Sleep(100);
                attempts++;

                if (attempts % 20 == 0)
                {
                    printf("  Waiting... (%d/%d)\n", attempts, maxAttempts);
                }
            }
        }
    }

    if (!targetModule)
    {
        printf("[-] Error: Failed to find target module\n");
        return false;
    }

    uintptr_t targetAddress = g_GetCurrentVendorAddr;
    if (targetAddress == 0) {
        printf("[+] No input address, using default address calculation");
        targetAddress = CalculateFunctionAddress(targetModule, GETCURRENTVENDOR_RVA);
        if (!targetAddress)
        {
            targetAddress = GETCURRENTVENDOR_ABSOLUTE;
            if (IsBadReadPtr((void*)targetAddress, 4))
            {
                printf("[!] Error: Hook address is not set!\n");
                return false;
            }
        }
    }
    else
    {
        if (targetAddress < 0x10000000) {
            printf("[*] Detected RVA offset. Adding module base...\n");
            targetAddress = (uintptr_t)targetModule + targetAddress;
        }
        else {
            printf("[*] Detected Absolute Address. Using directly.\n");
        }
    }

    printf("[+] Final Target Address: 0x%p\n", (void*)targetAddress);
    
    printf("[*] Checking target bytes at 0x%p: ", (void*)targetAddress);
    unsigned char* pBytes = (unsigned char*)targetAddress;
    if (IsBadReadPtr(pBytes, 16)) {
        printf("\n[-] Error: Target address is unreadable! (Access Violation)\n");
        return false;
    }

    for (int i = 0; i < 16; i++) {
        printf("%02X ", pBytes[i]);
    }
    printf("\n");

    bool isEmpty = true;
    for (int i = 0; i < 16; i++) {
        if (pBytes[i] != 0x00 && pBytes[i] != 0xCC) { isEmpty = false; break; }
    }
    if (isEmpty) {
        printf("[-] Error: Target memory is empty (00 or CC). Wrong address!\n");
        return false;
    }

    printf("[*] Installing hook at address: 0x%p\n", (void*)targetAddress);

    if (MH_Initialize() != MH_OK)
        return false;

    MH_STATUS status = MH_CreateHook((LPVOID)targetAddress, &HookedGetCurrentVendorEnvData, (LPVOID*)&originalGetCurrentVendor);
    if (status != MH_OK)
    {
        MH_Uninitialize();
        return false;
    }

    status = MH_EnableHook((LPVOID)targetAddress);
    if (status != MH_OK)
    {
        MH_Uninitialize();
        return false;
    }

    hooksInstalled = true;
    return true;
}

void CleanupHooks()
{
    if (hooksInstalled)
    {
        MH_DisableHook(MH_ALL_HOOKS);
        MH_Uninitialize();
        hooksInstalled = false;
    }
}

void CreateConsole()
{
    AllocConsole();

    FILE* fp;
    freopen_s(&fp, "CONOUT$", "w", stdout);
    freopen_s(&fp, "CONOUT$", "w", stderr);
    freopen_s(&fp, "CONIN$", "r", stdin);

    SetConsoleTitleA("StellaSora Hook Console");

    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
}

DWORD WINAPI HookInstallationThread(LPVOID lpParam)
{
    CreateConsole();

    printf("[*] Hook installation thread started\n");
    printf("[*] Waiting for global variable...\n");

    while (g_HookAddressVar == 0) {
        Sleep(10);
    }

    printf("[+] Address received via global var: 0x%p\n", (void*)g_HookAddressVar);
    g_GetCurrentVendorAddr = g_HookAddressVar;

    bool success = InstallHooks();

    if (success)
    {
        printf("[*] Hook installed successfully. Waiting for function calls...\n");
        while (true)
        {
            Sleep(10000);
        }
    }
    else
    {
        printf("[!] Hook installation failed.\n");
    }

    return success ? 1 : 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    HANDLE hThread = NULL;

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);

        hThread = CreateThread(
            NULL,
            0,
            HookInstallationThread,
            NULL,
            CREATE_SUSPENDED,
            NULL
        );

        if (hThread)
        {
            Sleep(10);
            ResumeThread(hThread);
            CloseHandle(hThread);
            OutputDebugStringA("[*] Hook installation thread started\n");
        }
        else
        {
            OutputDebugStringA("[!] Failed to create hook thread\n");
        }
        break;

    case DLL_PROCESS_DETACH:
        CleanupHooks();
        break;

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }

    return TRUE;
}