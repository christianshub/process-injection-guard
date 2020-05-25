//#include "ScanHiddenModules.h"
//
//MEMORY_BASIC_INFORMATION ScanHiddenModules::mbi = {};
//SYSTEM_INFO ScanHiddenModules::sysinfo = {};
//
//void ScanHiddenModules::Find(std::string signature, BOOL fullscan)
//{
//    int buffer = VirtualQuery((LPCVOID)mbi.RegionSize, &mbi, sizeof(mbi));
//
//    GetSystemInfo(&sysinfo);
//    for (unsigned int i = 0; i < (unsigned int)sysinfo.lpMaximumApplicationAddress; i += mbi.RegionSize++) {
//
//        size_t buf = VirtualQuery((LPCVOID)i, &mbi, sizeof(mbi));
//        if ((buf != 0) && (mbi.Type == MEM_PRIVATE) && (mbi.AllocationProtect == PAGE_EXECUTE_READWRITE))
//        {
//            //PrintMBI(mbi);
//
//            if ((mbi.Protect != PAGE_EXECUTE_READWRITE) && (mbi.Protect != PAGE_EXECUTE_READ) && (mbi.Protect != PAGE_READONLY) && (mbi.Protect != PAGE_READWRITE))
//            {
//                VirtualAlloc((LPVOID)i, mbi.RegionSize, MEM_COMMIT, PAGE_EXECUTE_READ);
//            }
//
//            FindSignature(signature, i, mbi.RegionSize, false);
//            VirtualAlloc((LPVOID)i, mbi.RegionSize, mbi.AllocationProtect, mbi.Protect);
//        }
//    }
//
//    std::cout << "[+] Done." << std::endl;
//}
//
//void ScanHiddenModules::PrintSystemInfo() {
//    SYSTEM_INFO sysinfo;
//    GetSystemInfo(&sysinfo);
//
//    std::cout << "SYSTEM INFO:  " << std::endl;
//    std::cout << " - DWORD dwPageSize " << sysinfo.dwPageSize << std::endl;
//    std::cout << " - lpMaximumApplicationAddress " << sysinfo.lpMaximumApplicationAddress << std::endl;
//    std::cout << std::endl;
//}
//
//void ScanHiddenModules::PrintMBI(MEMORY_BASIC_INFORMATION mbi) {
//
//    std::string StateText;
//    if (mbi.State == 0x1000)
//    {
//        StateText = "MEM_COMMIT"; // (Indicates committed pages for which physical storage has been allocated)
//    }
//    else if (mbi.State == 0x10000)
//    {
//        StateText = "MEM_FREE"; // (Indicates free pages not accessible to the calling process and available to be allocated.)
//    }
//    else if (mbi.State == 0x2000)
//    {
//        StateText = "MEM_RESERVE"; // (Indicates reserved pages where a range of the process's virtual address space is reserved without any physical storage being allocated.)
//    }
//    else
//    {
//        StateText = "UNDEFINED";
//    }
//
//    std::string TypeText;
//    if (mbi.Type == 0x1000000)
//    {
//        TypeText = "MEM_IMAGE";
//    }
//    else if (mbi.Type == 0x40000)
//    {
//        TypeText = "MEM_MAPPED";
//    }
//    else if (mbi.Type == 0x20000)
//    {
//        TypeText = "MEM_PRIVATE";
//    }
//    else if (mbi.Type == 0)
//    {
//        TypeText = "ZERO";
//    }
//    else
//    {
//        TypeText = "UNDEFINED";
//    }
//
//    std::string AllocProcText;
//    if (mbi.AllocationProtect == 0x10)
//    {
//        AllocProcText = "PAGE_EXECUTE";
//    }
//    else if (mbi.AllocationProtect == 0x20)
//    {
//        AllocProcText = "PAGE_EXECUTE_READ";
//    }
//    else if (mbi.AllocationProtect == 0x40)
//    {
//        AllocProcText = "PAGE_EXECUTE_READWRITE";
//    }
//    else if (mbi.AllocationProtect == 0x80)
//    {
//        AllocProcText = "PAGE_EXECUTE_WRITECOPY (ERWC-)";
//    }
//    else if (mbi.AllocationProtect == 0x01)
//    {
//        AllocProcText = "PAGE_NOACCESS";
//    }
//    else if (mbi.AllocationProtect == 0x02)
//    {
//        AllocProcText = "PAGE_READONLY (-R---)";
//    }
//    else if (mbi.AllocationProtect == 0x04)
//    {
//        AllocProcText = "PAGE_READWRITE (-RW--)";
//    }
//
//    else if (mbi.AllocationProtect == 0x08)
//    {
//        AllocProcText = "PAGE_WRITECOPY";
//    }
//
//    else if (mbi.AllocationProtect == 0x40000000)
//    {
//        AllocProcText = "PAGE_TARGETS_INVALID / PAGE_TARGETS_NO_UPDATE";
//    }
//
//    else if (mbi.AllocationProtect == 0x100)
//    {
//        AllocProcText = "PAGE_GUARD";
//    }
//
//    else if (mbi.AllocationProtect == 0x200)
//    {
//        AllocProcText = "PAGE_NOCACHE";
//    }
//
//    else if (mbi.AllocationProtect == 0x400)
//    {
//        AllocProcText = "PAGE_WRITECOMBINE";
//    }
//
//    else if (mbi.AllocationProtect == 0x0)
//    {
//        AllocProcText = "ZERO";
//    }
//
//    else if (mbi.AllocationProtect == 0x104)
//    {
//        AllocProcText = "UNDEFINED (-RW-G)";
//    }
//
//    else
//    {
//        AllocProcText = "UNDEFINED: " + std::to_string(mbi.Protect);
//    }
//
//    //////////////////////////////////////////////////////////////////////
//
//    std::string ProcText;
//    if (mbi.Protect == 0x10)
//    {
//        ProcText = "PAGE_EXECUTE";
//    }
//    else if (mbi.Protect == 0x20)
//    {
//        ProcText = "PAGE_EXECUTE_READ";
//    }
//    else if (mbi.Protect == 0x40)
//    {
//        ProcText = "PAGE_EXECUTE_READWRITE";
//    }
//    else if (mbi.Protect == 0x80)
//    {
//        ProcText = "PAGE_EXECUTE_WRITECOPY (ERWC-)";
//    }
//    else if (mbi.Protect == 0x01)
//    {
//        ProcText = "PAGE_NOACCESS";
//    }
//    else if (mbi.Protect == 0x02)
//    {
//        ProcText = "PAGE_READONLY (-R---)";
//    }
//    else if (mbi.Protect == 0x04)
//    {
//        ProcText = "PAGE_READWRITE (-RW--)";
//    }
//
//    else if (mbi.Protect == 0x08)
//    {
//        ProcText = "PAGE_WRITECOPY";
//    }
//
//    else if (mbi.Protect == 0x40000000)
//    {
//        ProcText = "PAGE_TARGETS_INVALID / PAGE_TARGETS_NO_UPDATE";
//    }
//
//    else if (mbi.Protect == 0x100)
//    {
//        ProcText = "PAGE_GUARD";
//    }
//
//    else if (mbi.Protect == 0x200)
//    {
//        ProcText = "PAGE_NOCACHE";
//    }
//
//    else if (mbi.Protect == 0x400)
//    {
//        ProcText = "PAGE_WRITECOMBINE";
//    }
//
//    else if (mbi.Protect == 0x0)
//    {
//        ProcText = "ZERO";
//    }
//
//    else if (mbi.Protect == 0x104)
//    {
//        ProcText = "UNDEFINED (-RW-G)";
//    }
//
//    else
//    {
//        ProcText = "UNDEFINED: " + std::to_string(mbi.Protect);
//    }
//
//    std::cout << "MEMORY_BASIC_INFORMATION:  " << std::endl;
//    std::cout << " - PVOID  BaseAddress (hex)      0x" << std::hex << std::uppercase << mbi.BaseAddress << std::endl;
//    std::cout << " - DWORD  AllocationProtect (text) " << AllocProcText << std::endl;
//    std::cout << " - SIZE_T RegionSize (hex)       0x" << std::hex << std::uppercase << mbi.RegionSize << std::endl;
//    std::cout << " - DWORD  State (text)             " << StateText << std::endl;
//    std::cout << " - DWORD  Protect (text)           " << ProcText << std::endl;
//    std::cout << " - DWORD  Type (text)              " << TypeText << "\n" << std::endl;
//}