#pragma once 
#include "../SigScan.h"
#include <windows.h>
#include <iostream>
#include "rfw_ntdll.h"
#include "../../Utility/Convertions.h"

namespace Scan {

    struct infoStruct {
        std::string name = "";
        std::string path = "";
        PVOID base = 0;
        ULONG size = 0;
    };
    
    std::string RunningFolder();
    void ModMemory(std::string signature, std::string moduleName = "ALL", std::string outputDir = RunningFolder());
    void PrivateERW(std::string signature, std::string outputDir = RunningFolder());

    std::vector<infoStruct> GetModuleInfo();

    
    void PrintMBI(MEMORY_BASIC_INFORMATION mbi, std::ostream& out);
}
