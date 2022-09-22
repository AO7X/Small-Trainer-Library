namespace Process {
    DWORD GetPID(const wchar_t *processName);
    HANDLE Open(const wchar_t *processName);
}

namespace Module {
    uintptr_t FindAddress(DWORD dwProcessID, const wchar_t *moduleName);
    uintptr_t GetAddress(const wchar_t *processName);
    uintptr_t GetAddress(const wchar_t *processName,
                         const wchar_t *moduleName);
}

namespace Memory {
    uintptr_t ResolveAddress(HANDLE hProcess, uintptr_t baseAddress,
                             std::vector <int> offsets);

    template <typename Type>
    Type Read(HANDLE hProcess, uintptr_t address) {
        Type value = 0;
        if (address) {
            ReadProcessMemory(hProcess, (LPCVOID *)address, &value,
                sizeof(value), NULL);
        }
        return value;
    }

    template <typename Type>
    Type Read(HANDLE hProcess, uintptr_t baseAddress,
              std::vector <int> offsets) {
        Type value = 0;
        if (baseAddress) {
            uintptr_t address = ResolveAddress(hProcess, baseAddress,
                offsets);
            if (address) {
                value = Read <Type> (hProcess, address);
            }
        }
        return value;
    }

    template <typename Type>
    void Write(HANDLE hProcess, uintptr_t address, Type value) {
        if (address) {
            WriteProcessMemory(hProcess, (LPVOID *)address, &value,
                sizeof(value), NULL);
        }
    }

    template <typename Type>
    void Write(HANDLE hProcess, uintptr_t baseAddress,
               std::vector <int> offsets, Type value) {
        if (baseAddress) {
            uintptr_t address = ResolveAddress(hProcess, baseAddress,
                offsets);
            if (address) {
                Write(hProcess, address, value);
            }
        }
    }

    void Patch(HANDLE hProcess, uintptr_t address, const wchar_t *binary);
    void Erase(HANDLE hProcess, uintptr_t address, int byteCount);
    uintptr_t ResolveAddress(uintptr_t baseAddress,
                             std::vector <int> offsets);

    template <typename Type>
    Type Read(uintptr_t address) {
        Type value = 0;
        if (address) {
            value = *(Type *)address;
        }
        return value;
    }

    template <typename Type>
    Type Read(uintptr_t baseAddress, std::vector <int> offsets) {
        Type value = 0;
        if (baseAddress) {
            uintptr_t address = ResolveAddress(baseAddress, offsets);
            if (address) {
                value = Read <Type> (address);
            }
        }
        return value;
    }

    template <typename Type>
    void Write(uintptr_t address, Type value) {
        if (address) {
            *(Type *)address = value;
        }
    }

    template <typename Type>
    void Write(uintptr_t baseAddress, std::vector <int> offsets,
               Type value) {
        if (baseAddress) {
            uintptr_t address = ResolveAddress(baseAddress, offsets);
            if (address) {
                Write(address, value);
            }
        }
    }

    void Patch(uintptr_t address, const wchar_t *binary);
    void Erase(uintptr_t address, int byteCount);
}