#include "../SigScan.h"
#include <windows.h>
#include <iostream>
#include "rfw_ntdll.h"
#include "../../Utility/Convertions.h"

namespace ScanModules {
    
    struct infoStruct {
        std::string name;
        std::string path;
        PVOID base;
        ULONG size;
    };


    std::vector<infoStruct> GetModuleInfo();    
    std::vector<infoStruct> container;
    
    void Find(std::string signature, BOOL fullscan);
    void Find(std::string signature, std::string moduleName, BOOL fullscan);

    MEMORY_BASIC_INFORMATION mbi;
    SYSTEM_INFO sysinfo;

    void PrintMBI(MEMORY_BASIC_INFORMATION mbi, std::ostream& out);
    void PrintSystemInfo(std::ostream& out);
}
