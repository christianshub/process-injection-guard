#include "ScanModules.h"

std::vector<ScanModules::infoStruct> ScanModules::GetModuleInfo()
{
    PEB* pPEB = (PEB*)__readfsdword(0x30);
    LDR_DATA_TABLE_ENTRY* Current = NULL;
    LIST_ENTRY* CurrentEntry = pPEB->Ldr->InMemoryOrderModuleList.Flink;

    std::vector<ScanModules::infoStruct> container;
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

std::string CreateFolder() 
{
    TCHAR NPath[MAX_PATH];
    GetCurrentDirectory(MAX_PATH, NPath);
    std::string folderPath = std::string(NPath) + "\\Dump";

    CreateDirectory(folderPath.c_str(), NULL);
    return folderPath;
}

void ScanModules::Find(std::string signature, BOOL fullscan)
{
    MEMORY_BASIC_INFORMATION mbi;
    std::string folder = CreateFolder();
    std::vector<infoStruct> container = GetModuleInfo();

    for (unsigned int i = 0; i < (unsigned int) container.size(); i++) {

        VirtualQuery((LPCVOID) container[i].base, &mbi, sizeof(mbi));

        for (unsigned int curAddress = (unsigned int) container[i].base; curAddress < ( ((unsigned int) container[i].base) + ((unsigned int) container[i].size) - 1); curAddress += mbi.RegionSize++) {

            size_t buf = VirtualQuery((LPCVOID)curAddress, &mbi, sizeof(mbi));
            if ( (buf != 0) && (mbi.Protect != PAGE_NOACCESS) && (mbi.Protect != 0) )
            {
                if ((mbi.Protect != PAGE_EXECUTE_READWRITE) && (mbi.Protect != PAGE_EXECUTE_READ) && (mbi.Protect != PAGE_READONLY) && (mbi.Protect != PAGE_READWRITE))
                {
                    VirtualAlloc((LPVOID) curAddress, mbi.RegionSize, MEM_COMMIT, PAGE_EXECUTE_READ);
                }

                std::string fileName = folder + "\\" + container[i].name + "_" + Convertions::INT_TO_HEXSTRING(curAddress) + ".txt";

                std::ofstream fout(fileName);
               
                std::cout << "[+] Scanning module " << container[i].name << " at address " << std::hex << std::uppercase << curAddress << "..." << std::endl;

                fout << "==================================================================================" << std::endl;
                fout << "MODULE INFORMATION:" << std::endl;
                fout << " - Base: " << container[i].base << std::endl;
                fout << " - Name: " << container[i].name << std::endl;
                fout << " - Path: " << container[i].path << std::endl;
                fout << " - Size: " << container[i].size << std::endl;

                PrintMBI(mbi, fout);
                
                SigScan::FindSignature(signature, curAddress, mbi.RegionSize, fout);

                fout.close();
            
            }
            VirtualAlloc((LPVOID)curAddress, mbi.RegionSize, mbi.AllocationProtect, mbi.Protect);
        }
    }

    std::cout << "[+] Done." << std::endl;
}

void ScanModules::Find(std::string signature, std::string moduleName, BOOL fullscan)
{
    std::vector<ScanModules::infoStruct> container = GetModuleInfo();
    for (unsigned int i = 0; i < (unsigned int) container.size(); i++) {
        if (container[i].name == moduleName) {
            
            std::cout << "base: " << container[i].base << std::endl;
            std::cout << "name: " << container[i].name << std::endl;
            std::cout << "path: " << container[i].path << std::endl;
            std::cout << "size: " << container[i].size << std::endl;

            //ScanModules::FindSignature(signature, (unsigned int) container[i].base, container[i].size, fullscan);
            // std::string Sig, unsigned int beginning, unsigned int size, bool fullscan
            
        }    
    }

    std::cout << "[+] Done." << std::endl;
}

void ScanModules::PrintMBI(MEMORY_BASIC_INFORMATION mbi, std::ostream& out) {

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

    out << "==================================================================================" << std::endl;
    out << "MEMORY BASIC INFORMATION:" << std::endl;
    out << " - BaseAddress          0x" << std::hex << std::uppercase << mbi.BaseAddress << std::endl;
    out << " - AllocationProtect    " << AllocProcText << std::endl;
    out << " - RegionSize           0x" << std::hex << std::uppercase << mbi.RegionSize << std::endl;
    out << " - State (text)         " << StateText << std::endl;
    out << " - Protect (text)       " << ProcText << std::endl;
    out << " - Type (text)          " << TypeText << std::endl;
}