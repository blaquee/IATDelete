#include <Windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <algorithm>

int main (int argc, char** argv)
{
    HMODULE thisModule = nullptr;
    PIMAGE_DOS_HEADER pDosHeader = nullptr;
    PIMAGE_NT_HEADERS pNtHeaders = nullptr;
    PIMAGE_SECTION_HEADER pSectionHeader = nullptr;
    PIMAGE_IMPORT_DESCRIPTOR pImportDesc = nullptr;
    PIMAGE_THUNK_DATA pThunkData = nullptr;

    DWORD_PTR dwImportDir = 0;
    std::string curDllName;

    // PCHAR pImageBase = 0;
    std::vector<std::string> sLibs = { "NTDLL.DLL", "KERNEL32.DLL" };

    thisModule = GetModuleHandle (nullptr);
    pDosHeader = (PIMAGE_DOS_HEADER)thisModule;
    pNtHeaders = (PIMAGE_NT_HEADERS)
        (((PUCHAR)thisModule) + pDosHeader->e_lfanew);

    pSectionHeader = IMAGE_FIRST_SECTION (pNtHeaders);
    if ((pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) > 0 &&
        (pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress) > 0)
    {
        // Import Descriptor Table exists.
        dwImportDir = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)(UINT_PTR)thisModule + dwImportDir;

        // IDT contains an array of Image Import Descriptors for each 
        // dll the exe imports (no delayed imports)
        /*
            + 0     DWORD   OriginalFirstThunk
            + 04	DWORD	TimeDateStamp
            + 08	DWORD	ForwarderChain
            + 0C	DWORD	Name
            + 10	DWORD	FirstThunk
        */
        while (pImportDesc->Name != 0)
        {
            curDllName = (const char*)thisModule + pImportDesc->Name;
            // are we interested in this dll?
            std::transform (curDllName.begin(), curDllName.end(),
                            curDllName.begin(),
                            [] (unsigned char c) {
                                return std::toupper (c);
                            });

            size_t found = curDllName.find(sLibs[0]);
            if (found == std::string::npos)
            {
                // dll not found, go to next entry
                pImportDesc++;
                continue;
            }

            // now we get to the THUNK data array describing the function pointers

        }

    }
}