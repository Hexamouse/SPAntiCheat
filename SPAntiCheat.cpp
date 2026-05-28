// =============================================================
// FILE: SPAntiCheat.cpp (SENDER - 64-BIT HEARTBEAT - FIXED)
// Fitur: 
// - 7x Advanced Debugger Detection
// - Self Integrity Check (CRC32)
// - 64-Bit Heartbeat (Anti-Overflow)
// - Process Blacklist Scanning
// =============================================================

#include "framework.h"
#include "SPAntiCheat.h"
#include <shellapi.h>
#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <aclapi.h>
#include <thread>
#include <chrono>
#include <vector>
#include <string>
#include <algorithm>
#include <fstream>
#include <ctime>
#include <iomanip>
#include <intrin.h> 

#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "version.lib")
#pragma comment(lib, "user32.lib")

#define MAX_LOADSTRING 100
#define WM_TRAYICON (WM_USER + 1)
#define TRAY_ICON_ID 1

// ================= GLOBAL CONFIG =================
HINSTANCE hInst;
WCHAR szTitle[MAX_LOADSTRING];
WCHAR szWindowClass[MAX_LOADSTRING];
NOTIFYICONDATA nid;
HWND hMainWnd = NULL;

const std::wstring TARGET_GAME = L"lostsaga.exe";
DWORD targetPID = 0;
HANDLE hGame = NULL;
bool gameHasStarted = false;

// SHARED MEMORY (64-BIT)
HANDLE hMapFile = NULL;
ULONGLONG* pSharedHeartbeat = NULL; // Menggunakan ULONGLONG (64-bit)
const LPCWSTR SHARED_MEM_NAME = L"Local\\SPAC_Heartbeat_V1";

// CRC32
unsigned int crc32_table[256];
DWORD originalCRC = 0;

// Daftar hitam tools cheat
std::vector<std::wstring> processBlacklist = {
    L"cheatengine", L"x32dbg", L"x64dbg", L"ollydbg",
    L"processhacker", L"procmon", L"wireshark", L"ida64",
    L"dnspy", L"netlimiter", L"ksdumper", L"httpdebugger",
    L"systeminformer", L"reclass", L"procexp"
};

// ================= HELPER FUNCTIONS =================

void InitLog() {
    std::ofstream logFile("SPAntiCheat.log", std::ios::trunc);
    if (logFile.is_open()) {
        time_t now = time(0);
        tm ltm;
        localtime_s(&ltm, &now);
        logFile << "========== SPAntiCheat Log Started ["
            << std::setfill('0') << std::setw(2) << ltm.tm_mday << "/"
            << std::setfill('0') << std::setw(2) << (ltm.tm_mon + 1) << "/"
            << (ltm.tm_year + 1900) << " "
            << std::setfill('0') << std::setw(2) << ltm.tm_hour << ":"
            << std::setfill('0') << std::setw(2) << ltm.tm_min << ":"
            << std::setfill('0') << std::setw(2) << ltm.tm_sec
            << "] ==========" << std::endl;
        logFile.close();
    }
}

void WriteLog(const std::string& text) {
    std::ofstream logFile("SPAntiCheat.log", std::ios::app);
    if (logFile.is_open()) {
        time_t now = time(0);
        tm ltm;
        localtime_s(&ltm, &now);
        logFile << "[" << std::setfill('0') << std::setw(2) << ltm.tm_hour << ":"
            << std::setfill('0') << std::setw(2) << ltm.tm_min << ":"
            << std::setfill('0') << std::setw(2) << ltm.tm_sec << "] "
            << text << std::endl;
        logFile.close();
    }
}

void TriggerAlarm() {
    Beep(1000, 300);
}

void UpdateTrayTooltip(const wchar_t* text) {
    wcscpy_s(nid.szTip, text);
    Shell_NotifyIcon(NIM_MODIFY, &nid);
}

std::wstring ToLower(std::wstring str) {
    std::transform(str.begin(), str.end(), str.begin(), ::tolower);
    return str;
}

std::string WStringToString(const std::wstring& wstr) {
    if (wstr.empty()) return std::string();
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
    return strTo;
}

// [FIX] Menambahkan kembali fungsi EnableDebugPrivilege yang hilang
bool EnableDebugPrivilege() {
    HANDLE hToken;
    LUID luid;
    TOKEN_PRIVILEGES tkp;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) return false;
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) return false;
    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Luid = luid;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL);
    CloseHandle(hToken);
    return true;
}

DWORD GetPIDByName(const std::wstring& name) {
    DWORD pid = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 entry;
        entry.dwSize = sizeof(entry);
        if (Process32First(snapshot, &entry)) {
            do {
                if (ToLower(entry.szExeFile) == ToLower(name)) {
                    pid = entry.th32ProcessID;
                    break;
                }
            } while (Process32Next(snapshot, &entry));
        }
        CloseHandle(snapshot);
    }
    return pid;
}

// ================= SECURITY MODULES =================

// INTEGRITY CHECK
void InitCRC32Table() {
    unsigned int c;
    for (int i = 0; i < 256; i++) {
        c = (unsigned int)i;
        for (int j = 0; j < 8; j++) {
            if (c & 1) c = 0xEDB88320L ^ (c >> 1);
            else c = c >> 1;
        }
        crc32_table[i] = c;
    }
}

DWORD CalculateFileCRC32(const std::wstring& filePath) {
    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return 0;

    const int bufferSize = 4096;
    char buffer[bufferSize];
    DWORD bytesRead;
    DWORD crc = 0xFFFFFFFF;

    while (ReadFile(hFile, buffer, bufferSize, &bytesRead, NULL) && bytesRead > 0) {
        for (DWORD i = 0; i < bytesRead; i++) {
            crc = crc32_table[(crc ^ buffer[i]) & 0xFF] ^ (crc >> 8);
        }
    }
    CloseHandle(hFile);
    return crc ^ 0xFFFFFFFF;
}

// DEBUGGER DETECTION
bool CheckDebuggersAdvanced() {
    if (IsDebuggerPresent()) return true;
    BOOL isRemote = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &isRemote);
    if (isRemote) return true;

    // Hardware Breakpoints
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(GetCurrentThread(), &ctx)) {
        if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0) return true;
    }

    // CloseHandle Trap
    __try { CloseHandle((HANDLE)0xDEADBEEF); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return true; }

    // Timing Check
    unsigned __int64 t1, t2;
    t1 = __rdtsc();
    GetTickCount64(); // [FIX] Menggunakan GetTickCount64 untuk menghindari Warning C28159
    t2 = __rdtsc();
    if ((t2 - t1) > 50000) return true;

    return false;
}

// ================= FORWARD DECLARATIONS =================
bool CheckDebuggerNtApi();
bool ScanSuspiciousWindows();
bool ScanSuspiciousDrivers();
bool ScanInjectedDLLs();
bool DetectExternalHandles();

// ================= CORE LOGIC =================

void InitSharedMemory() {
    hMapFile = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, sizeof(ULONGLONG), SHARED_MEM_NAME);
    if (hMapFile) pSharedHeartbeat = (ULONGLONG*)MapViewOfFile(hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(ULONGLONG));
}

void ForceCloseGame(const char* reason) {
    TriggerAlarm();
    WriteLog(std::string("SECURITY VIOLATION: ") + reason);

    if (pSharedHeartbeat) *pSharedHeartbeat = 0; // Signal KILL

    if (targetPID == 0) targetPID = GetPIDByName(TARGET_GAME);
    if (targetPID != 0) {
        HANDLE hKill = OpenProcess(PROCESS_TERMINATE, FALSE, targetPID);
        if (hKill) {
            TerminateProcess(hKill, 0);
            CloseHandle(hKill);
            WriteLog("Game Terminated.");
        }
    }
    if (hGame) { CloseHandle(hGame); hGame = NULL; }
    targetPID = 0;
    UpdateTrayTooltip(L"SPAntiCheat: Threat Neutralized!");
}

void ScanBlacklistedTools() {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 entry;
        entry.dwSize = sizeof(entry);
        if (Process32First(snapshot, &entry)) {
            do {
                std::wstring procName = ToLower(entry.szExeFile);
                for (const auto& badTool : processBlacklist) {
                    if (procName.find(badTool) != std::wstring::npos) {
                        WriteLog("DETECT: Blacklisted Tool -> " + WStringToString(procName));
                        HANDLE hBad = OpenProcess(PROCESS_TERMINATE, FALSE, entry.th32ProcessID);
                        if (hBad) { TerminateProcess(hBad, 1); CloseHandle(hBad); }
                        ForceCloseGame("Illegal Tool Detected");
                        CloseHandle(snapshot);
                        return;
                    }
                }
            } while (Process32Next(snapshot, &entry));
        }
        CloseHandle(snapshot);
    }
}

// ================= REGISTRY MODULE =================

const LPCWSTR REG_RUN_KEY = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";
const LPCWSTR REG_APP_KEY = L"SOFTWARE\\SPAntiCheat";
const LPCWSTR REG_VALUE_NAME = L"SPAntiCheat";

// 1. Auto-Start: Jalankan otomatis saat Windows boot
bool RegisterAutoStart() {
    WCHAR exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);

    HKEY hKey;
    LONG result = RegOpenKeyExW(HKEY_CURRENT_USER, REG_RUN_KEY, 0, KEY_SET_VALUE, &hKey);
    if (result != ERROR_SUCCESS) return false;

    result = RegSetValueExW(hKey, REG_VALUE_NAME, 0, REG_SZ,
        (const BYTE*)exePath, (DWORD)((wcslen(exePath) + 1) * sizeof(WCHAR)));
    RegCloseKey(hKey);

    if (result == ERROR_SUCCESS) {
        WriteLog("REGISTRY: Auto-start registered.");
        return true;
    }
    return false;
}

bool RemoveAutoStart() {
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, REG_RUN_KEY, 0, KEY_SET_VALUE, &hKey) != ERROR_SUCCESS)
        return false;
    LONG result = RegDeleteValueW(hKey, REG_VALUE_NAME);
    RegCloseKey(hKey);
    return result == ERROR_SUCCESS;
}

// 2. Simpan config ke Registry (CRC hash sebagai watchdog)
bool SaveConfigToRegistry() {
    HKEY hKey;
    DWORD disposition;
    LONG result = RegCreateKeyExW(HKEY_CURRENT_USER, REG_APP_KEY, 0, NULL,
        REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, &disposition);
    if (result != ERROR_SUCCESS) return false;

    // Simpan CRC hash anti-cheat sebagai referensi
    RegSetValueExW(hKey, L"IntegrityHash", 0, REG_DWORD,
        (const BYTE*)&originalCRC, sizeof(DWORD));

    // Simpan path executable
    WCHAR exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    RegSetValueExW(hKey, L"InstallPath", 0, REG_SZ,
        (const BYTE*)exePath, (DWORD)((wcslen(exePath) + 1) * sizeof(WCHAR)));

    // Simpan timestamp install
    ULONGLONG timestamp = GetTickCount64();
    RegSetValueExW(hKey, L"InstallTime", 0, REG_QWORD,
        (const BYTE*)&timestamp, sizeof(ULONGLONG));

    RegCloseKey(hKey);
    WriteLog("REGISTRY: Config saved.");
    return true;
}

// 3. Watchdog: Cek apakah registry di-tamper oleh cheater
bool VerifyRegistryIntegrity() {
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, REG_APP_KEY, 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        // Key tidak ada = pertama kali jalan, atau dihapus cheater
        WriteLog("REGISTRY: Config key missing - first run or tampered.");
        return false;
    }

    // Baca CRC yang tersimpan
    DWORD storedCRC = 0;
    DWORD dataSize = sizeof(DWORD);
    LONG result = RegQueryValueExW(hKey, L"IntegrityHash", NULL, NULL,
        (BYTE*)&storedCRC, &dataSize);
    RegCloseKey(hKey);

    if (result != ERROR_SUCCESS) return false;

    // Bandingkan dengan CRC aktual
    if (storedCRC != 0 && storedCRC != originalCRC) {
        WriteLog("REGISTRY: Integrity mismatch! File may be tampered.");
        return false;
    }

    return true;
}

// 4. Cek apakah auto-start masih terdaftar (anti-removal)
bool IsAutoStartIntact() {
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, REG_RUN_KEY, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return false;

    WCHAR value[MAX_PATH];
    DWORD dataSize = sizeof(value);
    LONG result = RegQueryValueExW(hKey, REG_VALUE_NAME, NULL, NULL, (BYTE*)value, &dataSize);
    RegCloseKey(hKey);

    return result == ERROR_SUCCESS;
}

// Forward declaration
void SetProcessCritical(bool enable);

// 5. Uninstall: Hapus semua registry entries dan log file
void CleanupAndUninstall() {
    SetProcessCritical(false); // WAJIB disable sebelum exit!

    RemoveAutoStart();
    WriteLog("UNINSTALL: Auto-start removed.");

    LONG result = RegDeleteKeyW(HKEY_CURRENT_USER, REG_APP_KEY);
    if (result == ERROR_SUCCESS) {
        WriteLog("UNINSTALL: Registry config key deleted.");
    }

    if (pSharedHeartbeat) { UnmapViewOfFile(pSharedHeartbeat); pSharedHeartbeat = NULL; }
    if (hMapFile) { CloseHandle(hMapFile); hMapFile = NULL; }
    if (hGame) { CloseHandle(hGame); hGame = NULL; }

    WriteLog("UNINSTALL: Cleanup complete. SPAntiCheat uninstalled.");
}


bool ProtectProcess() {
    HANDLE hProcess = GetCurrentProcess();

    // Buat SID untuk "Everyone"
    SID_IDENTIFIER_AUTHORITY worldAuth = SECURITY_WORLD_SID_AUTHORITY;
    PSID pEveryoneSid = NULL;
    if (!AllocateAndInitializeSid(&worldAuth, 1, SECURITY_WORLD_RID,
        0, 0, 0, 0, 0, 0, 0, &pEveryoneSid)) {
        WriteLog("PROTECT: Failed to create Everyone SID.");
        return false;
    }

    // Deny akses berbahaya: terminate, inject, suspend
    EXPLICIT_ACCESS denyAccess = { 0 };
    denyAccess.grfAccessPermissions = PROCESS_TERMINATE |
        PROCESS_VM_WRITE |
        PROCESS_VM_OPERATION |
        PROCESS_CREATE_THREAD |
        PROCESS_SUSPEND_RESUME;
    denyAccess.grfAccessMode = DENY_ACCESS;
    denyAccess.grfInheritance = NO_INHERITANCE;
    denyAccess.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    denyAccess.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    denyAccess.Trustee.ptstrName = (LPWSTR)pEveryoneSid;

    // Buat DACL baru dengan deny rule
    PACL pNewDacl = NULL;
    DWORD dwResult = SetEntriesInAcl(1, &denyAccess, NULL, &pNewDacl);
    if (dwResult != ERROR_SUCCESS) {
        FreeSid(pEveryoneSid);
        WriteLog("PROTECT: Failed to create ACL.");
        return false;
    }

    // Terapkan DACL ke proses sendiri
    dwResult = SetSecurityInfo(hProcess, SE_KERNEL_OBJECT,
        DACL_SECURITY_INFORMATION, NULL, NULL, pNewDacl, NULL);

    LocalFree(pNewDacl);
    FreeSid(pEveryoneSid);

    if (dwResult == ERROR_SUCCESS) {
        WriteLog("PROTECT: Process protection applied (Anti-Kill DACL).");
        return true;
    }

    WriteLog("PROTECT: Failed to apply process protection.");
    return false;
}

// ================= WATCHDOG & ENHANCED PROTECTION =================

// Function pointer type untuk RtlSetProcessIsCritical (ntdll)
typedef LONG(NTAPI* pRtlSetProcessIsCritical)(BOOLEAN bNew, BOOLEAN* pbOld, BOOLEAN bNeedScb);

// Set proses sebagai "critical" - killing akan menyebabkan BSOD (sangat agresif)
void SetProcessCritical(bool enable) {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return;

    auto fnRtlSetProcessIsCritical = (pRtlSetProcessIsCritical)
        GetProcAddress(hNtdll, "RtlSetProcessIsCritical");
    if (fnRtlSetProcessIsCritical) {
        BOOLEAN old;
        fnRtlSetProcessIsCritical(enable ? TRUE : FALSE, &old, FALSE);
        WriteLog(enable ? "PROTECT: Process marked as CRITICAL." : "PROTECT: Critical flag removed.");
    }
}

// Watchdog: Spawn salinan diri sendiri yang saling mengawasi
void SpawnWatchdog() {
    WCHAR exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);

    // Buat named mutex agar watchdog tahu parent masih hidup
    HANDLE hMutex = CreateMutexW(NULL, TRUE, L"Local\\SPAC_ParentAlive_V1");
    if (!hMutex) return;

    // Loop: jika mutex hilang (parent di-kill), respawn
    std::thread([]() {
        while (true) {
            Sleep(3000);
            // Cek apakah anti-cheat masih jalan
            HANDLE hCheck = OpenMutexW(SYNCHRONIZE, FALSE, L"Local\\SPAC_ParentAlive_V1");
            if (hCheck) {
                CloseHandle(hCheck);
            }
            else {
                // Parent di-kill! Langsung terminate game
                DWORD gamePID = GetPIDByName(TARGET_GAME);
                if (gamePID != 0) {
                    HANDLE hKill = OpenProcess(PROCESS_TERMINATE, FALSE, gamePID);
                    if (hKill) {
                        TerminateProcess(hKill, 0xDEAD0003);
                        CloseHandle(hKill);
                    }
                }
                // Respawn anti-cheat
                WCHAR path[MAX_PATH];
                GetModuleFileNameW(NULL, path, MAX_PATH);
                ShellExecuteW(NULL, L"runas", path, NULL, NULL, SW_HIDE);
                break;
            }
        }
    }).detach();
}

void AntiCheatLoop() {
    InitLog();
    EnableDebugPrivilege();
    ProtectProcess();
    SetProcessCritical(true);
    SpawnWatchdog();

    InitSharedMemory();
    InitCRC32Table();

    WCHAR path[MAX_PATH];
    GetModuleFileNameW(NULL, path, MAX_PATH);
    originalCRC = CalculateFileCRC32(path);
    WriteLog("SYSTEM: Integrity Hash: " + std::to_string(originalCRC));
    WriteLog("SYSTEM: Advanced Security Active.");

    RegisterAutoStart();
    SaveConfigToRegistry();

    int integrityCheckCounter = 0;
    int deepScanCounter = 0;

    while (true) {
        if (pSharedHeartbeat) {
            *pSharedHeartbeat = GetTickCount64();
        }

        // === FAST CHECKS (setiap loop / 500ms) ===
        if (CheckDebuggersAdvanced()) {
            ForceCloseGame("Advanced Debugger Detected");
        }

        if (CheckDebuggerNtApi()) {
            ForceCloseGame("NtAPI Debugger Detected");
        }

        targetPID = GetPIDByName(TARGET_GAME);

        if (targetPID != 0) {
            if (!hGame) {
                hGame = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_TERMINATE, FALSE, targetPID);
                UpdateTrayTooltip(L"SPAntiCheat: Protect");
                gameHasStarted = true;
            }

            ScanBlacklistedTools();

            // === MEDIUM CHECKS (setiap 5 loop / ~2.5 detik) ===
            deepScanCounter++;
            if (deepScanCounter > 5) {
                if (ScanSuspiciousWindows()) {
                    ForceCloseGame("Suspicious Window Detected");
                }

                if (ScanSuspiciousDrivers()) {
                    ForceCloseGame("Cheat Driver Detected");
                }

                deepScanCounter = 0;
            }

            // === SLOW CHECKS (setiap 10 loop / ~5 detik) ===
            integrityCheckCounter++;
            if (integrityCheckCounter > 10) {
                DWORD currentCRC = CalculateFileCRC32(path);
                if (currentCRC != originalCRC) ForceCloseGame("Anti-Cheat File Tampered/Patched");

                if (ScanInjectedDLLs()) {
                    ForceCloseGame("Suspicious DLL Injected into Game");
                }

                if (DetectExternalHandles()) {
                    ForceCloseGame("External Process Reading Game Memory");
                }

                if (!IsAutoStartIntact()) {
                    WriteLog("REGISTRY: Auto-start was removed! Re-registering...");
                    RegisterAutoStart();
                }

                if (!VerifyRegistryIntegrity()) {
                    SaveConfigToRegistry();
                }

                integrityCheckCounter = 0;
            }
        }
        else {
            if (gameHasStarted) {
                WriteLog("MONITOR: Game Closed. Exiting...");
                SetProcessCritical(false);
                if (hMainWnd) PostMessage(hMainWnd, WM_CLOSE, 0, 0);
                else exit(0);
                break;
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
}

// ================= WINDOWS GUI =================

void InitTrayIcon(HWND hWnd) {
    ZeroMemory(&nid, sizeof(nid));
    nid.cbSize = sizeof(NOTIFYICONDATA);
    nid.hWnd = hWnd;
    nid.uID = TRAY_ICON_ID;
    nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    nid.uCallbackMessage = WM_TRAYICON;
    nid.hIcon = LoadIcon(hInst, MAKEINTRESOURCE(IDI_ICON1));
    if (!nid.hIcon) nid.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    wcscpy_s(nid.szTip, L"SPAntiCheat: Active");
    Shell_NotifyIcon(NIM_ADD, &nid);
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
    case WM_TRAYICON:
        if (lParam == WM_RBUTTONUP) {
            POINT pt; GetCursorPos(&pt);
            SetForegroundWindow(hWnd);
            HMENU hMenu = CreatePopupMenu();
            int cmd = TrackPopupMenu(hMenu, TPM_RETURNCMD | TPM_NONOTIFY, pt.x, pt.y, 0, hWnd, NULL);
            if (cmd == 1002) {
                int confirm = MessageBoxW(hWnd,
                    L"Are you sure you want to uninstall SPAntiCheat?\n\n"
                    L"This will remove:\n"
                    L"  - Auto-start registry entry\n"
                    L"  - Configuration registry key\n"
                    L"  - Shared memory\n\n"
                    L"The game will also be closed if running.",
                    L"SPAntiCheat - Uninstall",
                    MB_YESNO | MB_ICONWARNING);
                if (confirm == IDYES) {
                    targetPID = GetPIDByName(TARGET_GAME);
                    if (targetPID != 0) ForceCloseGame("AC Uninstalled by User");
                    CleanupAndUninstall();
                    Shell_NotifyIcon(NIM_DELETE, &nid);
                    PostQuitMessage(0);
                }
            }
            DestroyMenu(hMenu);
        }
        break;

    case WM_CLOSE:
    case WM_DESTROY:
        if (pSharedHeartbeat) UnmapViewOfFile(pSharedHeartbeat);
        if (hMapFile) CloseHandle(hMapFile);
        targetPID = GetPIDByName(TARGET_GAME);
        if (targetPID != 0) ForceCloseGame("AC Closed Manually");
        Shell_NotifyIcon(NIM_DELETE, &nid);
        PostQuitMessage(0);
        break;

    default:
        return DefWindowProc(hWnd, message, wParam, lParam);
    }
    return 0;
}

int APIENTRY wWinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPWSTR lpCmdLine, _In_ int nCmdShow) {
    hInst = hInstance;
    wcscpy_s(szTitle, L"SPAntiCheat");
    wcscpy_s(szWindowClass, L"SPANTICHEAT_WND");

    HWND oldWnd = FindWindowW(szWindowClass, nullptr);
    if (oldWnd) { PostMessage(oldWnd, WM_CLOSE, 0, 0); std::this_thread::sleep_for(std::chrono::milliseconds(500)); }

    SetPriorityClass(GetCurrentProcess(), REALTIME_PRIORITY_CLASS);

    WNDCLASSEXW wcex = { sizeof(WNDCLASSEX) };
    wcex.lpfnWndProc = WndProc;
    wcex.hInstance = hInstance;
    wcex.lpszClassName = szWindowClass;
    wcex.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    RegisterClassExW(&wcex);

    hMainWnd = CreateWindowW(szWindowClass, szTitle, WS_OVERLAPPEDWINDOW, 0, 0, 0, 0, nullptr, nullptr, hInstance, nullptr);
    if (!hMainWnd) return FALSE;

    ShowWindow(hMainWnd, SW_HIDE);
    InitTrayIcon(hMainWnd);

    std::thread(AntiCheatLoop).detach();

    MSG msg;
    while (GetMessage(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return (int)msg.wParam;
}

// ================= WINDOW SCANNING =================

struct WindowScanResult {
    bool found;
    std::wstring detectedTitle;
};

std::vector<std::wstring> windowBlacklist = {
    L"cheat engine", L"ce main window", L"celua",
    L"x64dbg", L"x32dbg", L"ollydbg",
    L"ida -", L"ida pro", L"idafree",
    L"process hacker", L"system informer",
    L"reclass.net", L"reclass",
    L"http debugger", L"httpdebugger",
    L"dll injector", L"extreme injector",
    L"ghidra", L"binary ninja"
};

std::vector<std::wstring> classBlacklist = {
    L"WinDbgFrameClass",          // WinDbg
    L"PROCEXPL",                  // Process Explorer
    L"Qt5QWindowIcon",            // x64dbg, Ghidra (Qt apps)
    L"SunAwtFrame",               // Ghidra (Java)
};

BOOL CALLBACK EnumWindowsCallback(HWND hwnd, LPARAM lParam) {
    auto* result = (WindowScanResult*)lParam;

    WCHAR title[512] = { 0 };
    WCHAR className[256] = { 0 };
    GetWindowTextW(hwnd, title, 512);
    GetClassNameW(hwnd, className, 256);

    std::wstring titleLower = ToLower(title);
    std::wstring classLower = ToLower(className);

    for (const auto& bad : windowBlacklist) {
        if (titleLower.find(bad) != std::wstring::npos) {
            result->found = true;
            result->detectedTitle = title;
            return FALSE; // Stop enumerating
        }
    }

    for (const auto& bad : classBlacklist) {
        if (classLower.find(ToLower(bad)) != std::wstring::npos) {
            result->found = true;
            result->detectedTitle = className;
            return FALSE;
        }
    }

    return TRUE;
}

bool ScanSuspiciousWindows() {
    WindowScanResult result = { false, L"" };
    EnumWindows(EnumWindowsCallback, (LPARAM)&result);
    if (result.found) {
        WriteLog("DETECT: Suspicious Window -> " + WStringToString(result.detectedTitle));
    }
    return result.found;
}

// ================= DLL INJECTION DETECTION =================

// Daftar DLL yang sah (whitelist) - sesuaikan dengan game
std::vector<std::wstring> dllWhitelist = {
    L"kernel32.dll", L"ntdll.dll", L"user32.dll", L"gdi32.dll",
    L"advapi32.dll", L"shell32.dll", L"ws2_32.dll", L"wsock32.dll",
    L"d3d9.dll", L"d3d11.dll", L"dxgi.dll", L"opengl32.dll",
    L"msvcrt.dll", L"msvcp140.dll", L"vcruntime140.dll",
    L"lostsaga.exe",  // Module utama game
};

// DLL yang pasti berbahaya (blacklist)
std::vector<std::wstring> dllBlacklist = {
    L"speedhack", L"cheatengine", L"ce-mono",
    L"d3d9_proxy", L"opengl_hook",
};

// Tambahkan whitelist untuk path software sah
std::vector<std::wstring> trustedPaths = {
    L"\\program files\\",
    L"\\program files (x86)\\",
    L"\\windows\\",
    L"\\steam\\",
    L"\\discord\\",
    L"\\nvidia\\",
    L"\\amd\\",
    L"\\windhawk\\",
    L"\\microsoft\\",
    L"\\common files\\",
};

bool ScanInjectedDLLs() {
    if (targetPID == 0) return false;

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, targetPID);
    if (hSnap == INVALID_HANDLE_VALUE) return false;

    MODULEENTRY32W me = { 0 };
    me.dwSize = sizeof(me);

    bool suspicious = false;

    if (Module32FirstW(hSnap, &me)) {
        do {
            std::wstring modName = ToLower(me.szModule);
            std::wstring modPath = ToLower(me.szExePath);

            // Cek blacklist dulu
            for (const auto& bad : dllBlacklist) {
                if (modName.find(bad) != std::wstring::npos || modPath.find(bad) != std::wstring::npos) {
                    WriteLog("DETECT: Blacklisted DLL in game -> " + WStringToString(modName));
                    CloseHandle(hSnap);
                    return true;
                }
            }

            // Skip DLL dari trusted paths (Program Files, Windows, Steam, dll)
            bool isTrusted = false;
            for (const auto& trusted : trustedPaths) {
                if (modPath.find(trusted) != std::wstring::npos) {
                    isTrusted = true;
                    break;
                }
            }
            if (isTrusted) continue;

            // Cek lokasi sistem
            bool isSystem = modPath.find(L"\\windows\\system32\\") != std::wstring::npos ||
                            modPath.find(L"\\windows\\syswow64\\") != std::wstring::npos ||
                            modPath.find(L"\\windows\\winsxs\\") != std::wstring::npos;

            // Ambil folder game
            WCHAR gamePath[MAX_PATH];
            if (hGame) {
                GetModuleFileNameExW(hGame, NULL, gamePath, MAX_PATH);
                std::wstring gameDir = ToLower(gamePath);
                size_t lastSlash = gameDir.rfind(L'\\');
                if (lastSlash != std::wstring::npos) {
                    gameDir = gameDir.substr(0, lastSlash);
                    if (modPath.find(gameDir) != std::wstring::npos) isSystem = true;
                }
            }

            if (!isSystem) {
                WriteLog("SUSPECT: Unknown DLL -> " + WStringToString(modName) +
                         " Path: " + WStringToString(std::wstring(me.szExePath)));
                // Jangan langsung return true - hanya log saja untuk sekarang
                // suspicious = true;  // DIKOMENTARI untuk menghindari false positive
            }

        } while (Module32NextW(hSnap, &me));
    }

    CloseHandle(hSnap);
    return suspicious;
}

// ================= DEEP DEBUGGER DETECTION (NTAPI) =================

typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(
    HANDLE, ULONG, PVOID, ULONG, PULONG);

bool CheckDebuggerNtApi() {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return false;

    auto NtQIP = (pNtQueryInformationProcess)
        GetProcAddress(hNtdll, "NtQueryInformationProcess");
    if (!NtQIP) return false;

    // 1. ProcessDebugPort (0x07) - Paling reliable
    DWORD_PTR debugPort = 0;
    NTSTATUS status = NtQIP(GetCurrentProcess(), 7, &debugPort, sizeof(debugPort), NULL);
    if (status == 0 && debugPort != 0) {
        WriteLog("DETECT: NtAPI - DebugPort active.");
        return true;
    }

    // 2. ProcessDebugObjectHandle (0x1E)
    HANDLE debugObject = NULL;
    status = NtQIP(GetCurrentProcess(), 0x1E, &debugObject, sizeof(debugObject), NULL);
    if (status == 0) { // STATUS_SUCCESS = ada debug object
        WriteLog("DETECT: NtAPI - DebugObjectHandle found.");
        return true;
    }

    // 3. ProcessDebugFlags (0x1F) - 0 = being debugged
    DWORD debugFlags = 1;
    status = NtQIP(GetCurrentProcess(), 0x1F, &debugFlags, sizeof(debugFlags), NULL);
    if (status == 0 && debugFlags == 0) {
        WriteLog("DETECT: NtAPI - DebugFlags indicate debugging.");
        return true;
    }

    return false;
}

// ================= KERNEL DRIVER DETECTION =================

bool ScanSuspiciousDrivers() {
    // Nama-nama driver yang dipakai cheat tools
    std::vector<std::wstring> driverBlacklist = {
        L"dbk64.sys", L"dbk32.sys",           // Cheat Engine
        L"kprocesshacker.sys",                  // Process Hacker
        L"systeminformer.sys",                  // System Informer
        L"kdmapper.sys",                        // Manual mapper
        L"capcom.sys",                          // Capcom exploit
        L"iqvw64e.sys",                         // Intel vuln driver (exploit)
    };

    // Method 1: EnumDeviceDrivers
    LPVOID drivers[1024];
    DWORD cbNeeded;
    if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded)) {
        int driverCount = cbNeeded / sizeof(LPVOID);
        for (int i = 0; i < driverCount; i++) {
            WCHAR driverName[MAX_PATH];
            if (GetDeviceDriverBaseNameW(drivers[i], driverName, MAX_PATH)) {
                std::wstring name = ToLower(driverName);
                for (const auto& bad : driverBlacklist) {
                    if (name.find(ToLower(bad)) != std::wstring::npos) {
                        WriteLog("DETECT: Suspicious Driver -> " + WStringToString(name));
                        return true;
                    }
                }
            }
        }
    }

    // Method 2: Cek device handle yang dibuat Cheat Engine
    HANDLE hDevice = CreateFileW(L"\\\\.\\CEDRIVER73", GENERIC_READ, 0, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hDevice != INVALID_HANDLE_VALUE) {
        CloseHandle(hDevice);
        WriteLog("DETECT: Cheat Engine kernel driver device found!");
        return true;
    }

    return false;
}

// ================= HANDLE HIJACKING DETECTION =================

typedef NTSTATUS(NTAPI* pNtQuerySystemInformation)(
    ULONG SystemInformationClass, PVOID SystemInformation,
    ULONG SystemInformationLength, PULONG ReturnLength);

#pragma pack(push, 1)
typedef struct _SYSTEM_HANDLE_ENTRY {
    ULONG  ProcessId;
    BYTE   ObjectTypeNumber;
    BYTE   Flags;
    USHORT Handle;
    PVOID  Object;
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE_ENTRY;

typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG HandleCount;
    SYSTEM_HANDLE_ENTRY Handles[1];
} SYSTEM_HANDLE_INFORMATION;
#pragma pack(pop)

bool DetectExternalHandles() {
    if (targetPID == 0) return false;

    // Whitelist proses sistem yang sah
    std::vector<std::wstring> trustedProcesses = {
        L"svchost.exe",
        L"csrss.exe",
        L"lsass.exe",
        L"services.exe",
        L"wininit.exe",
        L"smss.exe",
        L"dwm.exe",
        L"explorer.exe",
        L"taskmgr.exe",
        L"msmpeng.exe",         // Windows Defender
        L"securityhealthservice.exe",
        L"mrt.exe",             // Malicious Software Removal Tool
        L"spanticheat.exe",     // Anti-cheat sendiri (lowercase)
    };

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return false;

    auto NtQSI = (pNtQuerySystemInformation)
        GetProcAddress(hNtdll, "NtQuerySystemInformation");
    if (!NtQSI) return false;

    ULONG bufferSize = 1024 * 1024;
    PVOID buffer = VirtualAlloc(NULL, bufferSize, MEM_COMMIT, PAGE_READWRITE);
    if (!buffer) return false;

    NTSTATUS status;
    while ((status = NtQSI(16, buffer, bufferSize, NULL)) == 0xC0000004L) {
        VirtualFree(buffer, 0, MEM_RELEASE);
        bufferSize *= 2;
        if (bufferSize > 64 * 1024 * 1024) return false;
        buffer = VirtualAlloc(NULL, bufferSize, MEM_COMMIT, PAGE_READWRITE);
        if (!buffer) return false;
    }

    if (status != 0) {
        VirtualFree(buffer, 0, MEM_RELEASE);
        return false;
    }

    auto* handleInfo = (SYSTEM_HANDLE_INFORMATION*)buffer;
    DWORD myPID = GetCurrentProcessId();
    bool suspicious = false;

    const ACCESS_MASK dangerousMask = PROCESS_VM_READ | PROCESS_VM_WRITE |
        PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD;

    for (ULONG i = 0; i < handleInfo->HandleCount; i++) {
        auto& h = handleInfo->Handles[i];

        if (h.ProcessId == myPID || h.ProcessId == targetPID ||
            h.ProcessId == 0 || h.ProcessId == 4) continue;

        if ((h.GrantedAccess & dangerousMask) != 0) {
            HANDLE hProc = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION,
                FALSE, h.ProcessId);
            if (hProc) {
                HANDLE dupHandle;
                if (DuplicateHandle(hProc, (HANDLE)(ULONG_PTR)h.Handle,
                    GetCurrentProcess(), &dupHandle, 0, FALSE, DUPLICATE_SAME_ACCESS)) {

                    DWORD handlePID = GetProcessId(dupHandle);
                    if (handlePID == targetPID) {
                        WCHAR procName[MAX_PATH] = { 0 };
                        GetModuleFileNameExW(hProc, NULL, procName, MAX_PATH);
                        std::wstring procNameLower = ToLower(procName);

                        // Cek apakah proses ada di whitelist
                        bool isTrusted = false;
                        for (const auto& trusted : trustedProcesses) {
                            if (procNameLower.find(trusted) != std::wstring::npos) {
                                isTrusted = true;
                                break;
                            }
                        }

                        // Cek path sistem
                        if (procNameLower.find(L"\\windows\\") != std::wstring::npos ||
                            procNameLower.find(L"\\program files\\") != std::wstring::npos ||
                            procNameLower.find(L"\\program files (x86)\\") != std::wstring::npos) {
                            isTrusted = true;
                        }

                        // [FIX] Cek apakah proses berasal dari folder game yang sama
                        if (!isTrusted && hGame) {
                            WCHAR gamePath[MAX_PATH];
                            GetModuleFileNameExW(hGame, NULL, gamePath, MAX_PATH);
                            std::wstring gameDir = ToLower(gamePath);
                            size_t lastSlash = gameDir.rfind(L'\\');
                            if (lastSlash != std::wstring::npos) {
                                gameDir = gameDir.substr(0, lastSlash);
                                if (procNameLower.find(gameDir) != std::wstring::npos) {
                                    isTrusted = true; // Proses dari folder game = trusted
                                }
                            }
                        }

                        if (!isTrusted) {
                            WriteLog("DETECT: External handle to game from PID " +
                                std::to_string(h.ProcessId) + " -> " + WStringToString(procName));
                            suspicious = true;
                        }
                    }
                    CloseHandle(dupHandle);
                }
                CloseHandle(hProc);
            }
        }
        if (suspicious) break;
    }

    VirtualFree(buffer, 0, MEM_RELEASE);
    return suspicious;
}