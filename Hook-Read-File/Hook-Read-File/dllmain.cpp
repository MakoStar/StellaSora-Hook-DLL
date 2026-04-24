#include <Windows.h>
#include <psapi.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <fstream>
#include <locale>
#include <codecvt>
#include <unordered_map>
#include <mutex>
#include "MinHook.h"

#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "libMinHook.x64.lib")

constexpr uintptr_t READFILE_RVA = 0x1041900;
constexpr uintptr_t READFILE_ABSOLUTE = 0x181041900;

using ReadFileByNameFunc = void* (__fastcall*)(void* archive, void* fileName);
ReadFileByNameFunc originalReadFileByName = nullptr;

std::ofstream hookFile;
bool hookFileInitialized = false;
bool hooksInstalled = false;
bool isTryingToHook = false;
int nameCallCount = 0;

uintptr_t g_GetReadFileAddr = 0;
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

std::mutex hookFileMutex;

std::ofstream& GetHookFileStream()
{
    std::lock_guard<std::mutex> lock(hookFileMutex);

    if (hookFileInitialized && hookFile.is_open())
        return hookFile;

    std::string fileName = "HookFile.txt";
    hookFile.open(fileName, std::ios::out | std::ios::trunc | std::ios::binary);

    if (hookFile.is_open())
    {
        hookFile.seekp(0, std::ios::end);
        std::streampos pos = hookFile.tellp();
        if (pos == 0)
        {
            unsigned char bom[] = { 0xEF, 0xBB, 0xBF };
            hookFile.write((const char*)bom, sizeof(bom));
            hookFile.flush();
        }

        hookFileInitialized = true;
        printf("[+] Created HookFile: %s\n", fileName.c_str());
    }
    else
    {
        printf("[-] Cannot open HookFile file: %s\n", fileName.c_str());
    }

    return hookFile;
}

void WriteFileNameToHookFile(void* /*archive*/, const std::string& fileNameUTF8)
{
    try
    {
        std::ofstream& f = GetHookFileStream();
        if (!f.is_open())
            return;

        std::string entry = fileNameUTF8 + "\n";
        f.write(entry.c_str(), entry.length());
        f.flush();
    }
    catch (...)
    {
        printf("[-] An exception occurred while writing to HookFile.txt\n");
    }
}

void CloseHookFile()
{
    std::lock_guard<std::mutex> lock(hookFileMutex);

    if (hookFileInitialized && hookFile.is_open())
    {
        hookFile.flush();
        hookFile.close();
        hookFileInitialized = false;
        printf("[+] Closed HookFile.txt\n");
    }
}

std::string WideToUTF8(const std::wstring& wstr)
{
    if (wstr.empty()) return "";

    int utf8Size = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.length(),
        nullptr, 0, nullptr, nullptr);
    if (utf8Size <= 0) return "";

    std::string result(utf8Size, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.length(),
        &result[0], utf8Size, nullptr, nullptr);
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

    printf("========================================\n");
    printf("Archive ReadFile Hook Console\n");
    printf("========================================\n\n");
}

void* __fastcall HookedReadFileByName(void* archive, void* fileName)
{
    nameCallCount++;
    std::wstring fileNameWide = GetStringFromIl2CppString(fileName);
    std::string fileNameUTF8 = WideToUTF8(fileNameWide);

    printf("[ReadFile(string)#%d]:\n", nameCallCount);
    printf("    Archive: 0x%p\n", archive);
    void* result = nullptr;

    if (originalReadFileByName)
    {
        result = originalReadFileByName(archive, fileName);

        if (result)
        {
            try
            {
                Il2CppArray* array = reinterpret_cast<Il2CppArray*>(result);

                if (!IsBadReadPtr(array, sizeof(Il2CppArray)))
                {
                    uintptr_t arraySize = array->max_length;

                    if (arraySize > 0)
                    {
                        printf("    FileName: %s\n", fileNameUTF8.c_str());
                        printf("    Size: %llu bytes\n", (unsigned long long)arraySize);
                        printf("========================================\n");
                        WriteFileNameToHookFile(archive, fileNameUTF8);
                    }
                    else
                    {
                        printf("  Warning: data size is 0\n");
                    }
                }
            }
            catch (...)
            {
                printf("  Error: failed to read data\n");
            }
        }
        else
        {
            printf("  Warning: return result is nullptr\n");
        }
    }
    else
    {
        printf("[Warning] Original function pointer is null!\n");
    }

    return result;
}

uintptr_t CalculateFunctionAddress(HMODULE module, uintptr_t rvaOffset)
{
    if (!module) return 0;

    uintptr_t baseAddress = (uintptr_t)module;
    uintptr_t functionAddress = baseAddress + rvaOffset;

    printf("[+] Module base address: 0x%p\n", (void*)baseAddress);
    printf("[+] RVA offset: 0x%X\n", (unsigned int)rvaOffset);
    printf("[+] Function address: 0x%p\n", (void*)functionAddress);

    if (IsBadReadPtr((void*)functionAddress, 4))
    {
        printf("[-] Warning: Calculated address is not readable\n");
        return 0;
    }

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
    const char* foundModuleName = nullptr;

    printf("[+] Searching for target module...\n");

    for (int i = 0; possibleModuleNames[i] != nullptr; i++)
    {
        targetModule = GetModuleHandleA(possibleModuleNames[i]);
        if (targetModule)
        {
            foundModuleName = possibleModuleNames[i];
            break;
        }
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
            else
            {
                foundModuleName = "GameAssembly.dll";
            }
        }
    }

    if (!targetModule)
    {
        printf("[-] Error: Failed to find target module\n");
        return false;
    }

    printf("========================================\n");
    printf("[+] Found module: %s! Module handle: 0x%p\n", foundModuleName, targetModule);


    uintptr_t targetAddress = g_GetReadFileAddr;
    if (targetAddress == 0) 
    {
        printf("[+] No input address, using default address calculation");
        targetAddress = CalculateFunctionAddress(targetModule, READFILE_RVA);
        if (!targetAddress)
        {
            targetAddress = READFILE_ABSOLUTE;
            if (IsBadReadPtr((void*)targetAddress, 4))
            {
                printf("[!] Error: Hook address is not set! Please call SetHookAddress first.\n");
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

    printf("========================================\n");
    printf("[+] Initializing MinHook...\n");
    if (MH_Initialize() != MH_OK)
    {
        printf("[-] MinHook initialization failed\n");
        return false;
    }

    printf("[+] Creating ReadFile(string) Hook...\n");
    
    MH_STATUS status = MH_CreateHook(
        (LPVOID)targetAddress,
        &HookedReadFileByName,
        (LPVOID*)&originalReadFileByName
    );

    if (status != MH_OK)
    {
        printf("[-] ReadFile(string) Hook creation failed: %d\n", status);
        MH_Uninitialize();
        return false;
    }

    printf("[+] Enabling ReadFile hook...\n");
    status = MH_EnableHook((LPVOID)targetAddress);
    if (status != MH_OK)
    {
        printf("[-] Enable hook failed: %d\n", status);
        MH_Uninitialize();
        return false;
    }

    GetHookFileStream();

    printf("[+] Hook installed successfully!\n");

    hooksInstalled = true;
    return true;
}

DWORD WINAPI HookInstallationThread(LPVOID lpParam)
{
    isTryingToHook = true;

    CreateConsole();

    printf("[+] Hook installation thread started\n");
    
    printf("[*] Waiting for global variable...\n");

    while (g_HookAddressVar == 0) {
        Sleep(10);
    }

    printf("[+] Address received via global var: 0x%p\n", (void*)g_HookAddressVar);
    g_GetReadFileAddr = g_HookAddressVar;

    bool success = InstallHooks();

    if (success)
    {
        printf("\n========================================\n");
        printf("[+] HOOK installed successfully!\n");
        printf("[+] Waiting for ReadFile(string) to be called...\n");

        while (true)
        {
            Sleep(10000);
            printf("[Hooking] ReadFile(string) call %d count.\n", nameCallCount);

        }
    }
    else
    {
        printf("\n========================================\n");
        printf("[-] HOOK installation failed!\n");
        printf("[-] Possible reasons:\n");
        printf("[-] 1. Incorrect function address\n");
        printf("[-] 2. Game version mismatch\n");
        printf("========================================\n\n");
    }

    isTryingToHook = false;
    return success ? 1 : 0;
}

void CleanupHooks()
{
    printf("[+] Cleaning up hooks...\n");

    CloseHookFile();

    if (hooksInstalled)
    {
        MH_DisableHook(MH_ALL_HOOKS);
        MH_Uninitialize();
        hooksInstalled = false;
    }

    printf("[+] Cleanup complete\n");
    printf("[+] Total calls: ReadFile(string)=%d\n", nameCallCount);
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

            OutputDebugStringA("[ArchiveReadFileHook] Hook installation thread started\n");
        }
        else
        {
            OutputDebugStringA("[ArchiveReadFileHook] Failed to create hook thread\n");
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