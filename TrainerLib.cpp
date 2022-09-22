#include "pch.h"
#include <Windows.h>
#include <TlHelp32.h>
#include <vector>
#include <iostream>
#include "TrainerLib.h"

DWORD Process::GetPID(const wchar_t *processName) {
    DWORD dwProcessID = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 processEntry;
        processEntry.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hSnapshot, &processEntry)) {
            do {
                if (!wcscmp(processEntry.szExeFile, processName)) {
                    dwProcessID = processEntry.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnapshot, &processEntry));
        }
    }
    CloseHandle(hSnapshot);
    return dwProcessID;
}

HANDLE Process::Open(const wchar_t *processName) {
    DWORD dwProcessID = GetPID(processName);
    if (dwProcessID) {
        return OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessID);
    }
    return NULL;
}

uintptr_t Module::FindAddress(DWORD dwProcessID,
                              const wchar_t *moduleName) {
    uintptr_t moduleAddress = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE |
        TH32CS_SNAPMODULE32, dwProcessID);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        MODULEENTRY32 moduleEntry;
        moduleEntry.dwSize = sizeof(MODULEENTRY32);
        if (Module32First(hSnapshot, &moduleEntry)) {
            do {
                if (!wcscmp(moduleEntry.szModule, moduleName)) {
                    moduleAddress = (uintptr_t)moduleEntry.modBaseAddr;
                    break;
                }
            } while (Module32Next(hSnapshot, &moduleEntry));
        }
    }
    CloseHandle(hSnapshot);
    return moduleAddress;
}

uintptr_t Module::GetAddress(const wchar_t *processName) {
    DWORD dwProcessID = Process::GetPID(processName);
    if (dwProcessID) {
        return FindAddress(dwProcessID, processName);
    }
    return NULL;
}

uintptr_t Module::GetAddress(const wchar_t *processName,
                             const wchar_t *moduleName) {
    DWORD dwProcessID = Process::GetPID(processName);
    if (dwProcessID) {
        return FindAddress(dwProcessID, moduleName);
    }
    return NULL;
}

uintptr_t Memory::ResolveAddress(HANDLE hProcess, uintptr_t baseAddress,
                                 std::vector <int> offsets) {
    uintptr_t address = baseAddress;
    for (int i = 0; i < offsets.size(); i++) {
        ReadProcessMemory(hProcess, (LPVOID *)address, &address,
            sizeof(address), 0);
        address += offsets[i];
    }
    return address;
}

void Memory::Patch(HANDLE hProcess, uintptr_t address,
                   const wchar_t *binary) {
    size_t returnValue = 0;
    char *convertedBinary = (char *)malloc(sizeof(binary));
    wcstombs_s(&returnValue, convertedBinary, sizeof(binary), binary,
        sizeof(binary));
    DWORD dwOldProtect = 0;
    VirtualProtectEx(hProcess, (LPVOID *)address, wcslen(binary),
        PAGE_EXECUTE_READWRITE, &dwOldProtect);
    WriteProcessMemory(hProcess, (LPVOID *)address,
        (LPCVOID *)convertedBinary, wcslen(binary), 0);
    VirtualProtectEx(hProcess, (LPVOID *)address, wcslen(binary),
        dwOldProtect, &dwOldProtect);
}

void Memory::Erase(HANDLE hProcess, uintptr_t address, int byteCount) {
    for (int i = 0; i < byteCount; i++) {
        Patch(hProcess, address + i, L"\x90");
    }
}

uintptr_t Memory::ResolveAddress(uintptr_t baseAddress,
                                 std::vector <int> offsets) {
    uintptr_t address = baseAddress;
    for (int i = 0; i < offsets.size(); i++) {
        address = *(uintptr_t *)address;
        address += offsets[i];
    }
    return address;
}

void Memory::Patch(uintptr_t address, const wchar_t *binary) {
    size_t returnValue = 0;
    char *convertedBinary = (char *)malloc(sizeof(binary));
    wcstombs_s(&returnValue, convertedBinary, sizeof(binary), binary,
        sizeof(binary));
    DWORD dwOldProtect = 0;
    VirtualProtect((LPVOID *)address, wcslen(binary),
        PAGE_EXECUTE_READWRITE, &dwOldProtect);
    memcpy((void *)address, (const void *)convertedBinary, wcslen(binary));
    VirtualProtect((LPVOID *)address, wcslen(binary), dwOldProtect,
        &dwOldProtect);
}

void Memory::Erase(uintptr_t address, int byteCount) {
    for (int i = 0; i < byteCount; i++) {
        Patch(address + i, L"\x90");
    }
}