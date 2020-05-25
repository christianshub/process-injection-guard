#pragma once 
#include "../SigScan.h"
#include <windows.h>
#include <iostream>
#include "rfw_ntdll.h"
#include "../../Utility/Convertions.h"

namespace ScanModules {

    struct infoStruct {
        std::string name = "";
        std::string path = "";
        PVOID base = 0;
        ULONG size = 0;
    };
    
    void Find(std::string signature, BOOL fullscan);
    void Find(std::string signature, std::string moduleName, BOOL fullscan);

    std::vector<infoStruct> GetModuleInfo();

    void PrintMBI(MEMORY_BASIC_INFORMATION mbi, std::ostream& out);
    void PrintSystemInfo(std::ostream& out);
}
