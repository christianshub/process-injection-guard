#include "../SigScan.h"
#include <windows.h>
#include <iostream>
#include "rfw_ntdll.h"
#include "../../Utility/Convertions.h"

class ScanModules : SigScan
{
    struct infoStruct {
        std::string name;
        std::string path;
        PVOID base;
        ULONG size;
    };
    static std::vector<infoStruct> GetModuleInfo();
public:
    static std::vector<infoStruct> container;
    static void Find(std::string signature, BOOL fullscan);
    static void Find(std::string signature, std::string moduleName, BOOL fullscan);

    static MEMORY_BASIC_INFORMATION mbi;
    static SYSTEM_INFO sysinfo;

    static void PrintMBI(MEMORY_BASIC_INFORMATION mbi);
    static void PrintSystemInfo();
};
