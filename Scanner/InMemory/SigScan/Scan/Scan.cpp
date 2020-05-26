#include "Scan.h"

std::vector<Scan::infoStruct> Scan::GetModuleInfo()
{
    PEB* pPEB = (PEB*)__readfsdword(0x30);
    LDR_DATA_TABLE_ENTRY* Current = NULL;
    LIST_ENTRY* CurrentEntry = pPEB->Ldr->InMemoryOrderModuleList.Flink;

    std::vector<infoStruct> container;
    container.clear();

    while (CurrentEntry != &pPEB->Ldr->InMemoryOrderModuleList && CurrentEntry != NULL)
    {
        Current = CONTAINING_RECORD(CurrentEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

        infoStruct info;

        info.name = Convertions::TO_STRING(Current->BaseDllName.Buffer);
        info.path = Convertions::TO_STRING(Current->FullDllName.Buffer);
        info.base = Current->DllBase;
        info.size = Current->SizeOfImage;

        container.push_back(info);

        CurrentEntry = CurrentEntry->Flink;
    }
    return container;
}

std::string Scan::RunningFolder() 
{
    TCHAR NPath[MAX_PATH];
    GetCurrentDirectory(MAX_PATH, NPath);
    std::string folderPath = std::string(NPath);

    return folderPath;
}


void Scan::PrivateERW(std::string signature, std::string outputDir)
{
    SYSTEM_INFO sysinfo = {};
    MEMORY_BASIC_INFORMATION mbi = {};

    outputDir += "\\Dump";

    std::cout << "outputDir create at " << outputDir << std::endl;
    CreateDirectory(outputDir.c_str(), NULL);

    VirtualQuery(0, &mbi, sizeof(mbi));

    GetSystemInfo(&sysinfo);

    for (unsigned int i = 0; i < (unsigned int)sysinfo.lpMaximumApplicationAddress; i += mbi.RegionSize++) {

        size_t buf = VirtualQuery((LPCVOID)i, &mbi, sizeof(mbi));
        if ((buf != 0) && (mbi.Type == MEM_PRIVATE) && (mbi.AllocationProtect == PAGE_EXECUTE_READWRITE))
        {
            std::string fileName = outputDir + "\\" + Convertions::INT_TO_HEXSTRING(i) + "_" + ".txt";
            std::ofstream fout(fileName);

            if ((mbi.Protect != PAGE_EXECUTE_READWRITE) && (mbi.Protect != PAGE_EXECUTE_READ) && (mbi.Protect != PAGE_READONLY) && (mbi.Protect != PAGE_READWRITE))
            {
                VirtualAlloc((LPVOID)i, mbi.RegionSize, MEM_COMMIT, PAGE_EXECUTE_READ);
            }

            SigScan::FindSignature(signature, i, mbi.RegionSize, fout);
            VirtualAlloc((LPVOID)i, mbi.RegionSize, mbi.AllocationProtect, mbi.Protect);

            fout.close();
        }  
    }

    std::cout << "[+] Done." << std::endl;
}

void Scan::ModMemory(std::string signature, std::string moduleName, std::string outputDir)
{
    MEMORY_BASIC_INFORMATION mbi;
    
    outputDir += "\\Dump";
    std::cout << "Folder create at " << outputDir << std::endl;
    CreateDirectory(outputDir.c_str(), NULL);

    std::vector<infoStruct> container = GetModuleInfo();


    int iterator = 0;
    int containerLength = container.size();

    if (moduleName != "ALL") {
        for (iterator; iterator < containerLength; iterator++) {
            if (container[iterator].name == moduleName) 
            {
                containerLength = iterator + 1;
                break;
            }
        }  
    }

    for (iterator; iterator < containerLength; iterator++) {

        VirtualQuery((LPCVOID) container[iterator].base, &mbi, sizeof(mbi));

        std::string fileName = outputDir + "\\" + container[iterator].name + "_" + ".txt";
        std::ofstream fout(fileName);

        fout << "==================================================================================" << std::endl;
        fout << "MODULE INFORMATION:" << std::endl;
        fout << " - Base: " << container[iterator].base << std::endl;
        fout << " - Name: " << container[iterator].name << std::endl;
        fout << " - Path: " << container[iterator].path << std::endl;
        fout << " - Size: " << container[iterator].size << std::endl;
        fout << "==================================================================================\n" << std::endl;

        // BASIC SCAN
        for (unsigned int curAddress = (unsigned int) container[iterator].base; curAddress < ( ((unsigned int) container[iterator].base) + ((unsigned int) container[iterator].size) - 1); curAddress += mbi.RegionSize++) {

            size_t buf = VirtualQuery((LPCVOID)curAddress, &mbi, sizeof(mbi));
            if ( (buf != 0) && (mbi.Protect != PAGE_NOACCESS) && (mbi.Protect != 0) )
            {
                if ((mbi.Protect != PAGE_EXECUTE_READWRITE) && (mbi.Protect != PAGE_EXECUTE_READ) && (mbi.Protect != PAGE_READONLY) && (mbi.Protect != PAGE_READWRITE))
                {
                    VirtualAlloc((LPVOID) curAddress, mbi.RegionSize, MEM_COMMIT, PAGE_EXECUTE_READ);
                }

                std::cout << "[+] Scanning module " << container[iterator].name << " at address " << std::hex << std::uppercase << curAddress << "..." << std::endl;

                PrintMBI(mbi, fout);
                
                SigScan::FindSignature(signature, curAddress, mbi.RegionSize, fout);
            }
            VirtualAlloc((LPVOID)curAddress, mbi.RegionSize, mbi.AllocationProtect, mbi.Protect);
        }
        
        fout.close();
    }

    std::cout << "[+] Done." << std::endl;
}



void Scan::PrintMBI(MEMORY_BASIC_INFORMATION mbi, std::ostream& out) {

    std::string StateText;
    std::string TypeText;
    std::string AllocProcText;
    std::string ProcText;

    switch (mbi.State) {
    case 0x1000:
        StateText = "MEM_COMMIT";
        break;
    case 0x10000:
        StateText = "MEM_FREE";
        break;
    case 0x2000:
        StateText = "MEM_RESERVE";
        break;
    default: //Optional
        StateText = "UNDEFINED";
        break;
    }

    switch (mbi.Type) {
    case 0x1000000:
        TypeText = "MEM_IMAGE";
        break;
    case 0x40000:
        TypeText = "MEM_MAPPED";
        break;
    case 0x20000:
        TypeText = "MEM_PRIVATE";
        break;
    case 0x0:
        TypeText = "ZERO";
        break;
    default: //Optional
        StateText = "UNDEFINED";
        break;
    }


    switch (mbi.AllocationProtect) {
    case 0x10:
        AllocProcText = "PAGE_EXECUTE";
        break;
    case 0x20:
        AllocProcText = "PAGE_EXECUTE_READ";
        break;
    case 0x40:
        AllocProcText = "PAGE_EXECUTE_READWRITE";
        break;
    case 0x80:
        AllocProcText = "PAGE_EXECUTE_WRITECOPY (ERWC-)";
        break;
    case 0x01:
        AllocProcText = "PAGE_NOACCESS";
        break;
    case 0x02:
        AllocProcText = "PAGE_READONLY (-R---)";
        break;
    case 0x04:
        AllocProcText = "PAGE_READWRITE (-RW--)";
        break;
    case 0x08:
        AllocProcText = "PAGE_WRITECOPY";
        break;
    case 0x40000000:
        AllocProcText = "PAGE_TARGETS_INVALID / PAGE_TARGETS_NO_UPDATE";
        break;
    case 0x100:
        AllocProcText = "PAGE_GUARD";
        break;
    case 0x200:
        AllocProcText = "PAGE_NOCACHE";
        break;
    case 0x400:
        AllocProcText = "PAGE_WRITECOMBINE";
        break;
    case 0x104:
        AllocProcText = "UNDEFINED (-RW-G)";
        break;
    case 0x0:
        AllocProcText = "ZERO";
        break;
    default:
        AllocProcText = "UNDEFINED: " + std::to_string(mbi.Protect);
        break;
    }

    switch (mbi.Protect) {
    case 0x10:
        ProcText = "PAGE_EXECUTE";
        break;
    case 0x20:
        ProcText = "PAGE_EXECUTE_READ";
        break;
    case 0x40:
        ProcText = "PAGE_EXECUTE_READWRITE";
        break;
    case 0x80:
        ProcText = "PAGE_EXECUTE_WRITECOPY (ERWC-)";
        break;
    case 0x01:
        ProcText = "PAGE_NOACCESS";
        break;
    case 0x02:
        ProcText = "PAGE_READONLY (-R---)";
        break;
    case 0x04:
        ProcText = "PAGE_READWRITE (-RW--)";
        break;
    case 0x08:
        ProcText = "PAGE_WRITECOPY";
        break;
    case 0x40000000:
        ProcText = "PAGE_TARGETS_INVALID / PAGE_TARGETS_NO_UPDATE";
        break;
    case 0x100:
        ProcText = "PAGE_GUARD";
        break;
    case 0x200:
        ProcText = "PAGE_NOCACHE";
        break;
    case 0x400:
        ProcText = "PAGE_WRITECOMBINE";
        break;
    case 0x104:
        ProcText = "UNDEFINED (-RW-G)";
        break;
    case 0x0:
        ProcText = "ZERO";
        break;
    default:
        ProcText = "UNDEFINED: " + std::to_string(mbi.Protect);
        break;
    }

    out << "MEMORY BASIC INFORMATION:" << std::endl;
    out << " - BaseAddress          0x" << std::hex << std::uppercase << mbi.BaseAddress << std::endl;
    out << " - AllocationProtect    " << AllocProcText << std::endl;
    out << " - RegionSize           0x" << std::hex << std::uppercase << mbi.RegionSize << std::endl;
    out << " - State (text)         " << StateText << std::endl;
    out << " - Protect (text)       " << ProcText << std::endl;
    out << " - Type (text)          " << TypeText << std::endl;
}