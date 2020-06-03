#include "SigScanner.h"

std::vector<infoStruct> GetModuleInfo()
{
    std::string filePath = VerifyINI("Detection", "config.ini", { "[Config]", "Signature=", "Module=",  "AutoHook=", "AutoScan=" });
    std::string content = ReadKey("Config", "Module", filePath);
 
    PEB* pPEB = (PEB*)__readfsdword(0x30);
    LDR_DATA_TABLE_ENTRY* Current = NULL;
    LIST_ENTRY* CurrentEntry = pPEB->Ldr->InMemoryOrderModuleList.Flink;

    std::vector<infoStruct> container;
    container.clear();

    while (CurrentEntry != &pPEB->Ldr->InMemoryOrderModuleList && CurrentEntry != NULL)
    {
        Current = CONTAINING_RECORD(CurrentEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

        infoStruct info;

        info.name = PCWSTR_TO_STRING(Current->BaseDllName.Buffer);
        info.path = PCWSTR_TO_STRING(Current->FullDllName.Buffer);
        info.base = Current->DllBase;
        info.size = Current->SizeOfImage;

        if ((content.length() == 0) || (ToLowercase(content).find(ToLowercase(info.name)) != std::string::npos))
        {
            container.push_back(info);
        }

        CurrentEntry = CurrentEntry->Flink;
    }
    return container;
}

void ManualMapScan(std::string signature)
{

    SYSTEM_INFO sysinfo = {};
    MEMORY_BASIC_INFORMATION mbi = {};

    std::string path = CreateFolder(GetDesktopPath(), "Detection\\DumpPrivateERW");
    std::string fileName = path + "\\" + "sig_" + signature + ".txt";

    std::ofstream fout(fileName);

    VirtualQuery(0, &mbi, sizeof(mbi));

    GetSystemInfo(&sysinfo);

    for (unsigned int i = 0; i < (unsigned int)sysinfo.lpMaximumApplicationAddress; i += mbi.RegionSize++) {

        size_t buf = VirtualQuery((LPCVOID)i, &mbi, sizeof(mbi));
        if ((buf != 0) && (mbi.Type == MEM_PRIVATE) && (mbi.AllocationProtect == PAGE_EXECUTE_READWRITE))
        {

            //if ((mbi.Protect != PAGE_EXECUTE_READWRITE) && (mbi.Protect != PAGE_EXECUTE_READ) && (mbi.Protect != PAGE_READONLY) && (mbi.Protect != PAGE_READWRITE))
            if (mbi.Protect != PAGE_EXECUTE_READ)
            
            {
                //std::cout << "Address " << std::hex << i << " will be changed!" << std::endl;
                //std::cout << "Sleep 30 seconds!" << std::endl;
                //Sleep(60000);
                VirtualAlloc((LPVOID)i, mbi.RegionSize, MEM_COMMIT, PAGE_EXECUTE_READ);
                //VirtualProtect((LPVOID)i, mbi.RegionSize, PAGE_EXECUTE_READ, &mbi.Protect);


                //std::cout << "CHANGED!" << std::endl;
            }

            //std::cout << "[+] Scanning for signature '" << signature << "' at address " << std::hex << std::uppercase << i << "..." << std::endl;

            PrintMBI(mbi, fout);

            FindSignature(signature, i, mbi.RegionSize, fout);
            VirtualAlloc((LPVOID)i, mbi.RegionSize, mbi.AllocationProtect, mbi.Protect);

            
        }  
    }

    fout.close();

    std::cout << "[+] Done." << std::endl;
}

void ScanAll(std::string signature)
{

    SYSTEM_INFO sysinfo = {};
    MEMORY_BASIC_INFORMATION mbi = {};

    std::string path = CreateFolder(GetDesktopPath(), "Detection\\AllDump");
    std::string fileName = path + "\\" + "sig_" + signature + ".txt";

    std::ofstream fout(fileName);

    VirtualQuery(0, &mbi, sizeof(mbi));

    GetSystemInfo(&sysinfo);

    for (unsigned int i = 0; i < (unsigned int)sysinfo.lpMaximumApplicationAddress; i += mbi.RegionSize++) {

        size_t buf = VirtualQuery((LPCVOID)i, &mbi, sizeof(mbi));
        PrintMBI(mbi, std::cout);
        Sleep(5000);

        DWORD oldProtect = mbi.Protect;
        DWORD newProtect = 0x40;
        VirtualProtect((LPVOID)i, mbi.RegionSize, newProtect, &oldProtect);

        //VirtualQuery((LPCVOID)i, &mbi, sizeof(mbi));

        Sleep(5000);

        VirtualProtect((LPVOID)i, mbi.RegionSize, oldProtect, &newProtect);

        Sleep(5000);
        //VirtualAlloc((LPVOID)i, mbi.RegionSize, PAGE_NOACCESS, PAGE_EXECUTE_READWRITE);
        //VirtualAlloc((LPVOID)i, mbi.RegionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

        PrintMBI(mbi, std::cout);
    }
 

    fout.close();

    std::cout << "[+] Done." << std::endl;
}

void ModuleScan(std::string signature)
{
    MEMORY_BASIC_INFORMATION mbi;
    
    std::string path = CreateFolder(GetDesktopPath(), "Detection\\DumpModules");
    std::vector<infoStruct> container = GetModuleInfo();

    for (size_t iterator = 0; iterator < container.size(); iterator++) {

        VirtualQuery((LPCVOID) container[iterator].base, &mbi, sizeof(mbi));

        std::string fileName = path + "\\" + "sig_" + signature + "_mod_" + container[iterator].name + ".txt";
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

                //std::cout << "[+] Scanning " << container[iterator].name << " for signature '" << signature << "' at address " << std::hex << std::uppercase << curAddress << "..." << std::endl;

                PrintMBI(mbi, fout);
                
                FindSignature(signature, curAddress, mbi.RegionSize, fout);
            }
            VirtualAlloc((LPVOID)curAddress, mbi.RegionSize, mbi.AllocationProtect, mbi.Protect);
        }
        
        fout.close();
    }

    std::cout << "[+] Done." << std::endl;
}

void PrintMBI(MEMORY_BASIC_INFORMATION mbi, std::ostream& out) {

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



std::string Sig = "";                       // full or masked signature: e.g.: "4d5a90"/"4d??90"
std::string FirstSigByte = "";              // we start by comparing each byte with the signature's initial bytes.
std::string Buffer = "";                    // holds the signature found byte by byte.

unsigned int ByteIterator = 0;              // is iterating over all bytes.
unsigned int SequenceIterator = 0;          // is starting to iterate when the initial byte signature is found.

std::map<int, std::string> Container = {};  // will be used if "fullscan" is enabled. In case there are more signatures.


void PrintContainer(std::ostream& out)
{
    if (Container.size() != 0)
    {
        std::cout << std::endl;
        for (auto& x : Container)
        {
            out << "[SIGNATURE FOUND] [ Address: " << std::uppercase << std::hex << std::setw(8) << std::setfill('0') << x.first << " | Signature: " << x.second << " ]" << std::endl;
            std::cout << "[SIGNATURE FOUND] [ Address: " << std::uppercase << std::hex << std::setw(8) << std::setfill('0') << x.first << " | Signature: " << x.second << " ]" << std::endl;
        }
        out << std::endl;
        std::cout << std::endl;
    }
    else
    {
        out << "[-] No signatures found.\n" << std::endl;
        //std::cout << "[-] No signatures found.\n" << std::endl;
    }
}

std::string CurrentByte()
{
    return hexStr((PBYTE)(ByteIterator + SequenceIterator), 1);
}

// Converts bytes to a readable string (hex representation).
std::string hexStr(BYTE* data, int len)
{
    std::stringstream ss;
    ss << std::hex;

    for (int i = 0; i < len; ++i)
        ss << std::setw(2) << std::setfill('0') << (int)data[i];

    return ss.str();
}


// public
void FindSignature(std::string signature, unsigned int address, ULONG size, std::ostream& out)
{
    out << "SIGNATURE SCAN:" << std::endl;
    out << " - Signature:           " << signature << std::endl;
    out << " - Start address:       0x" << std::hex << std::uppercase << address << std::endl;
    out << " - Page size:           0x" << std::hex << size << std::endl;
    out << " - End address:         0x" << std::hex << (address + size - 1) << std::endl;

    FirstSigByte = signature.substr(0, 2); // Get the first byte from Sig.
    Container.clear();               // Clear the Container for patterns before initiation.

    for (ByteIterator = address; ByteIterator < (address+size-1); ByteIterator++)
    {
        // If first byte of signature is equal to current byte, we may have a pattern.
        // (e.g.: FirstSigByte: "4d", CurrentByte(): "4d" 
        if (FirstSigByte.compare(CurrentByte()) == 0)
        {
            // We compare pair-wise, so we only need half of the iterations
            for (SequenceIterator = 0; SequenceIterator < (signature.length() / 2); SequenceIterator++)
            {

                if (signature.substr(SequenceIterator * 2, 2).compare("??") == 0)
                {
                    Buffer.append("??");
                }

                // Success if the next byte in signature is equal to current byte
                else if (signature.substr(SequenceIterator * 2, 2).compare(CurrentByte()) == 0)
                {
                   Buffer.append(CurrentByte());
                }
                else
                {
                    // No match anyway, clear buffer and reset
                    Buffer.clear();
                    break;
                }
            }

            // If mask and buffer are equal (e.g.: "4d??90" == "4d??90" 
            if (signature.compare(Buffer) == 0)
            {
                Container.insert(std::pair<int, std::string>(ByteIterator + SequenceIterator - (signature.length()/2), Buffer));
                Buffer.clear();
            }
            else 
            {
                Buffer.clear();
            }
        }
    }

    PrintContainer(out);
}