#include "SigScanner.h"

// 
// GET MODULE LIST
//

void GetModuleInfo(std::vector<infoStruct> &container, std::string content)
{
    PEB* pPEB = (PEB*)__readfsdword(0x30);
    LDR_DATA_TABLE_ENTRY* Current = NULL;
    LIST_ENTRY* CurrentEntry = pPEB->Ldr->InMemoryOrderModuleList.Flink;

    while (CurrentEntry != &pPEB->Ldr->InMemoryOrderModuleList && CurrentEntry != NULL)
    {
        Current = CONTAINING_RECORD(CurrentEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

        infoStruct info;

        info.name = PCWSTR_TO_STRING(Current->BaseDllName.Buffer);
        info.path = PCWSTR_TO_STRING(Current->FullDllName.Buffer);
        info.base = Current->DllBase;
        info.size = Current->SizeOfImage;

        if ( (content.length() == 0) || content.find(info.name) != std::string::npos)
        {
            container.push_back(info);
        }

        CurrentEntry = CurrentEntry->Flink;
    }
}


// 
// MANUAL MAP SCAN
//


void ManualMapScan(std::string signature)
{
    SYSTEM_INFO sysinfo = {};
    MEMORY_BASIC_INFORMATION mbi = {};

    VirtualQuery(0, &mbi, sizeof(mbi));

    GetSystemInfo(&sysinfo);

    for (unsigned int i = 0; i < (unsigned int)sysinfo.lpMaximumApplicationAddress; i += mbi.RegionSize++) {

        size_t buf = VirtualQuery((LPCVOID)i, &mbi, sizeof(mbi));
        if ((buf != 0) && (mbi.AllocationProtect == PAGE_EXECUTE_READWRITE) && (mbi.Protect != 0))
        {
            std::cout << "[+] Scanning in suspect memory regions for signature '" << signature << "' at address " << std::hex << std::uppercase << i << "..." << std::endl;

            DWORD changedProtect = PAGE_EXECUTE_READ;
    
            if ((mbi.Protect != PAGE_EXECUTE_READWRITE) && (mbi.Protect != PAGE_EXECUTE_READ) && (mbi.Protect != PAGE_READONLY) && (mbi.Protect != PAGE_READWRITE))            
            {
                VirtualProtect((LPVOID)i, mbi.RegionSize, changedProtect, &mbi.Protect);
            }

            PrintContainer(FindSignature(signature, i, mbi.RegionSize));

            VirtualProtect((LPVOID)i, mbi.RegionSize, mbi.Protect, &changedProtect);
        }  
    }

    std::cout << "\n[+] Done.\n" << std::endl;
}


// 
// MODULE SCANNER
//


void ModuleScan(std::string signature, std::string modules)
{
    MEMORY_BASIC_INFORMATION mbi;
    
    std::vector<infoStruct> container = {};
    GetModuleInfo(container, modules);

    for (size_t i = 0; i < container.size(); i++) {

        VirtualQuery((LPCVOID) container[i].base, &mbi, sizeof(mbi));

        for (unsigned int curAddress = (unsigned int) container[i].base; curAddress < ( ((unsigned int) container[i].base) + ((unsigned int) container[i].size) - 1); curAddress += mbi.RegionSize++) {

            size_t buf = VirtualQuery((LPCVOID)curAddress, &mbi, sizeof(mbi));
            if ((buf != 0) && (mbi.Protect != 0))
            {
                DWORD changedProtect = PAGE_EXECUTE_READ;

                if ((mbi.Protect != PAGE_EXECUTE_READWRITE) && (mbi.Protect != PAGE_EXECUTE_READ) && (mbi.Protect != PAGE_READONLY) && (mbi.Protect != PAGE_READWRITE))
                {
                    VirtualProtect((LPVOID)curAddress, mbi.RegionSize, changedProtect, &mbi.Protect);
                }

                std::cout << "[+] Scanning in module '" << container[i].name << "' for signature '" << signature << "' at address " << std::hex << std::uppercase << curAddress << "..." << std::endl;

                PrintContainer(FindSignature(signature, curAddress, mbi.RegionSize));
                VirtualProtect((LPVOID)curAddress, mbi.RegionSize, mbi.Protect, &changedProtect);
            }
        }
    }

    std::cout << "\n[+] Done.\n" << std::endl;
}



// 
// SIGNATURE SCANNER
//


void PrintContainer(std::map<int, std::string> Container)
{
    if (Container.size() != 0)
    {
        std::cout << std::endl;
        for (auto& x : Container)
        {
            std::cout << "[SIGNATURE FOUND] [ Address: " << std::uppercase << std::hex << std::setw(8) << std::setfill('0') << x.first << " | Signature: " << x.second << " ]" << std::endl;
        }
        std::cout << std::endl;
    }
}

std::string CurrentByte(unsigned int index)
{
    std::stringstream ss;
    ss << std::hex;

    ss << std::setw(2) << std::setfill('0') << (int)((PBYTE)(index))[0];

    return ss.str();
}

std::map<int, std::string> FindSignature(std::string signature, unsigned int address, ULONG size)
{
    std::string Buffer = "";
    std::string FirstSigByte = signature.substr(0, 2); // Get the first byte from Sig.

    std::map<int, std::string> Container;

    unsigned int i = address;
    unsigned int j = 0;
    
    while (i < (address + size - 1))
    {
       // If first byte of signature is equal to current byte, we may have a pattern.
       // (e.g.: FirstSigByte: "4d", CurrentByte(): "4d" 
       if (FirstSigByte.compare(CurrentByte(i)) == 0)
       {
           while (j < (signature.length() / 2))
           {
               if (signature.substr(j * 2, 2).compare("??") == 0)
               {
                   Buffer.append("??");
               }

               // Success if the next byte in signature is equal to current byte
               else if (signature.substr(j * 2, 2).compare(CurrentByte(i + j)) == 0)
               {
                   Buffer.append(CurrentByte(i + j));
               }
               else
               {
                   // No match anyway, clear buffer and reset
                   Buffer.clear();
                   break;
               }

               j++;
           }

           // If mask and buffer are equal (e.g.: "4d??90" == "4d??90" 
           if (signature.compare(Buffer) == 0)
           {
               Container.insert(std::pair<int, std::string>(i + j - (signature.length() / 2), Buffer));
               Buffer.clear();
           }
           else
           {
               Buffer.clear();
           }
       }
       j = 0;
       i++;
    }

    return Container;
}