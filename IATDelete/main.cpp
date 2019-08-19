#include <Windows.h>
#include <dbghelp.h>
#include <iostream>
#include <vector>
#include <string>
#include <algorithm>

#pragma comment(lib, "dbghelp.lib")

void RemoveImportReferences(PVOID Base)
{
    PIMAGE_DOS_HEADER pDosHeader = nullptr;
    PIMAGE_NT_HEADERS pNtHeaders = nullptr;
    PIMAGE_IMPORT_DESCRIPTOR pImportDesc = nullptr;
    DWORD oldProtection;
    //DWORD dwImportTableAddr;

    pDosHeader = (PIMAGE_DOS_HEADER)Base;
    pNtHeaders = (PIMAGE_NT_HEADERS)RVA_TO_ADDR(pDosHeader, pDosHeader->e_lfanew);


    // Make it RW
    VirtualProtect((PVOID)& pNtHeaders->OptionalHeader.DataDirectory,
                   sizeof(IMAGE_OPTIONAL_HEADER), PAGE_READWRITE, &oldProtection);
    pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = 0;
    pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = 0;
    pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size = 0;
    pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress = 0;
    //restore
    VirtualProtect((PVOID)& pNtHeaders->OptionalHeader.DataDirectory,
                   sizeof(IMAGE_OPTIONAL_HEADER), oldProtection, nullptr);
    return;
}
 
void RemoveModuleEntry(PVOID Base, PIMAGE_IMPORT_DESCRIPTOR ImportDesc)
{
    PIMAGE_THUNK_DATA pThunkData = nullptr;
    PIMAGE_IMPORT_BY_NAME pImportByName = nullptr;
    std::string curDllName;

    if (!Base || !ImportDesc)
    {
        std::cout << "Nothing happened" << std::endl;
        return;
    }
    // Lets zero the module name
    DWORD oldProtect;
    VirtualProtect(ImportDesc,
                   sizeof(IMAGE_IMPORT_DESCRIPTOR),
                   PAGE_READWRITE, &oldProtect);
    ImportDesc->Name = 0;
    VirtualProtect(ImportDesc,
                   sizeof(IMAGE_IMPORT_DESCRIPTOR),
                   oldProtect, nullptr);

    curDllName = (const char*)Base + ImportDesc->Name;
    std::cout << "New Module Name: " << curDllName << std::endl;


}
int main (int argc, char** argv)
{
    HMODULE thisModule = nullptr;
    PIMAGE_DOS_HEADER pDosHeader = nullptr;
    PIMAGE_NT_HEADERS pNtHeaders = nullptr;
    PIMAGE_SECTION_HEADER pSectionHeader = nullptr;
    PIMAGE_IMPORT_DESCRIPTOR pImportDesc = nullptr;
    PIMAGE_IMPORT_DESCRIPTOR pFirstImportDesc = nullptr;
    PIMAGE_THUNK_DATA pThunkData = nullptr;
    PIMAGE_THUNK_DATA pFirstThunkData = nullptr;
    PIMAGE_IMPORT_BY_NAME pImportByName = nullptr;
    BOOL bContainsThunk = FALSE;
    ULONG size = 0;

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
        pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToDataEx(
            thisModule,
            TRUE,
            IMAGE_DIRECTORY_ENTRY_IMPORT,
            &size,
            nullptr);

        // Import Descriptor Entry Table contains an array of Image Import Descriptors for each 
        // dll the exe imports from (no delayed imports)
        /*
            + 0     DWORD   OriginalFirstThunk
            + 04	DWORD	TimeDateStamp
            + 08	DWORD	ForwarderChain
            + 0C	DWORD	Name
            + 10	DWORD	FirstThunk
        */
        while (pImportDesc->Name != 0)
        {
            
            curDllName = ((const char*)thisModule + pImportDesc->Name);
            std::cout << "Module: " << curDllName << std::endl;
            std::cout << "Import Desc: " << pImportDesc << std::endl;
            // The Image Import Descriptors contain a pointer to an array of 
            // IMAGE_THUNK_DATA's that describe pointers to the functions

            // iterate through the thunks
            // sometimes originalfirstthunk can be 0
            if (pImportDesc->OriginalFirstThunk != 0)
            {
                // OriginalFirstThunk contains the array of names for the
                // imported functions
                pThunkData = (PIMAGE_THUNK_DATA)
                    RVA_TO_ADDR(pDosHeader, pImportDesc->OriginalFirstThunk);
                bContainsThunk = TRUE;
            }
            // First thunk contains the array of addresses for the 
            // imported functions
            pFirstThunkData = (PIMAGE_THUNK_DATA)RVA_TO_ADDR(
                pDosHeader, pImportDesc->FirstThunk);
            
            
            // iterate function names, if original first thunk is 0, then firstthunk contains the
            // array of names and will need to be resolved instead.
            if (bContainsThunk)
            {
                while (pThunkData->u1.AddressOfData != 0)
                {
                    // iterate the functions or ordinals
                    if (pThunkData->u1.Ordinal & IMAGE_ORDINAL_FLAG)
                    {
                        // ordinal (not supported in this poc)
                        break;
                    }
                    // get the name
                    pImportByName = (PIMAGE_IMPORT_BY_NAME)
                        RVA_TO_ADDR(pDosHeader, pThunkData->u1.AddressOfData);

                    DWORD_PTR dwFirstThunkAddress = (pFirstThunkData->u1.Function == 0) ? 0 : pFirstThunkData->u1.Function;
                    std::cout << "\tFunction: " << (char*)pImportByName->Name <<
                        "\tAddr: " << std::hex << dwFirstThunkAddress << std::endl;

                    pThunkData++;
                    pFirstThunkData++;
                }
                pImportDesc++;
            }

        } // while:end

        //DebugBreak();
        RemoveImportReferences(thisModule);

        std::cout << "Reference Removed from OptionalHeader\n";
        std::cin.get();        
    }
    return 0;
}