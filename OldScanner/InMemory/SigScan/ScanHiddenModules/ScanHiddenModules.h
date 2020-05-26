#include "..\SigScan.h"
#include <windows.h>

class ScanHiddenModules : SigScan
{

public:

    static MEMORY_BASIC_INFORMATION mbi;
    static SYSTEM_INFO sysinfo;
    static void Find(std::string signature, BOOL fullscan);

private:

    static void PrintMBI(MEMORY_BASIC_INFORMATION mbi);
    static void PrintSystemInfo();
};