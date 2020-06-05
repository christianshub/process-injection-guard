#pragma once 

#include <windows.h>
#include <iostream>
#include <map>
#include "x64dbg_ntdll.h"
#include "../Utility/Convertions.h"
#include "../Utility/StrManipulation.h"

#define DLLEXPORT __declspec(dllexport)

struct infoStruct {
    std::string name = "";
    std::string path = "";
    PVOID base = 0;
    ULONG size = 0;
};
    
/// <summary>
/// Save the PEB's module info to a vector container.
/// </summary>
/// <param name="container">Insert an empty container, the function fills it with module info elements</param>
/// <param name="content">Insert module names to search through, if "", we get all modules</param>
DLLEXPORT void GetModuleInfo(std::vector<infoStruct>&container, std::string content);

/// <summary>
/// Scan through modules for signatures
/// </summary>
/// <param name="signature">full or masked signature: e.g.: "4d5a90"/"4d??90"</param>
/// <param name="modules">module list as a string, e.g.: "ntdll.dll,kernel32.dll"</param>
DLLEXPORT void ModuleScan(std::string signature, std::string modules);

/// <summary>
/// Scans memory regions where the Manual Map injection technique
/// tends to hide their payloads.
/// </summary>
DLLEXPORT void ManualMapScan(std::string signature);

/// <summary>
/// Scans for signatures from within a memory's address space.
/// </summary>
/// <param name="signature"> full or masked signature: e.g.: "4d5a90"/"4d??90" </param>
/// <param name="address">   start address                                     </param>
/// <param name="size">      scan size                                         </param>
/// <returns>                                   
/// Container with an address and corrosponding string 
/// </returns>
DLLEXPORT std::map<int, std::string> FindSignature(std::string signature, unsigned int address, ULONG size);

/// <summary>
/// Converts a byte at an index to std::string
/// </summary>
DLLEXPORT std::string CurrentByte(unsigned int index);

/// <summary>
/// Prints the final results
/// </summary>
DLLEXPORT void PrintContainer(std::map<int, std::string> Container);