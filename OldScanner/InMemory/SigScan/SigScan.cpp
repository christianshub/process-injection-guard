#include "SigScan.h"
#include <string>     // std::string, std::stol
#include "../Utility/DumpOutput.h"
#include "windows.h"

//MEMORY_BASIC_INFORMATION ScanHiddenModules::mbi = {};
//
//    int buffer = VirtualQuery((LPCVOID)mbi.RegionSize, &mbi, sizeof(mbi));
//
//    GetSystemInfo(&sysinfo);
//    for (unsigned int i = 0; i < (unsigned int)sysinfo.lpMaximumApplicationAddress; i += mbi.RegionSize++) {
//
//        size_t buf = VirtualQuery((LPCVOID)i, &mbi, sizeof(mbi));

std::string SigScan::Sig =          "";              
std::string SigScan::FirstSigByte = "";              
std::string SigScan::Buffer =       "";              
long long SigScan::ByteIterator = 0;
long long SigScan::SequenceIterator = 0;
std::map<int, std::string> SigScan::Container = {}; 

// Converts bytes to a readable string (hex representation).
std::string SigScan::hexStr(BYTE* data, int len)
{
    std::stringstream ss;
    ss << std::hex;

    for (int i = 0; i < len; ++i)
        ss << std::setw(2) << std::setfill('0') << (int)data[i];

    return ss.str();
}


// public:
void SigScan::FindSignature(std::string Sig, unsigned int beginning, ULONG size, bool fullscan)
{
    MEMORY_BASIC_INFORMATION mbi = {};

    size_t buf = VirtualQuery((LPCVOID)beginning, &mbi, sizeof(mbi));
    //int buffer = VirtualQuery((LPCVOID)mbi.RegionSize, &mbi, sizeof(mbi));

    TCHAR NPath[MAX_PATH];
    GetCurrentDirectory(MAX_PATH, NPath);
    //std::cout << NPath << std::endl;
    

    std::string path = NPath;
    std::string fpath = path + "\\Dump";

    CreateDirectory(fpath.c_str(), NULL);
    std::cout << "fpath: " << fpath << std::endl;
    std::string fname = (fpath + "\\" + std::to_string(beginning) + ".txt");
    std::cout << "fname: " << fname << std::endl;
    std::ofstream fout(fname);

    std::cout << "\n[+] Scanning address '" << std::hex << std::uppercase << beginning << "' for signature '" << Sig;
    std::cout << "' size '0x" << std::hex << size << "', fullscan: " << fullscan << std::endl;

    fout << "=========== Beginning ===========" << std::endl;
    fout << "- Parameters:" << std::endl;
    fout << "    Sig         0x" << std::hex << Sig << std::endl;
    fout << "    beginning   0x" << std::hex << beginning << std::endl;
    fout << "    size        0x" << std::hex << size << std::endl;
    fout << "    size          " << std::dec << size << std::endl;
    //fout << "    RegionSize (hex) 0x" << std::hex << std::uppercase << mbi.RegionSize << std::endl;
    fout << "    fullscan      " << fullscan << std::endl;

    fout << "- Other:" << std::endl;
    fout << "    ByteIterator  " << ByteIterator << std::endl;
    fout << "    begin+size  0x" << std::hex << (beginning + size - 1) << std::endl;
    fout << "    Sig.length  0x" << std::hex << Sig.length() << "\n" << std::endl;
   
    FirstSigByte = Sig.substr(0, 2); // Get the first byte from Sig.
    Container.clear();               // Clear the Container for patterns before initiation.

    fout << "=========== ByteIterator for-loop ===========" << std::endl;
    for (ByteIterator = beginning; ByteIterator < (beginning+size-1); ByteIterator++)
    {

        size_t buf = VirtualQuery((LPCVOID)ByteIterator, &mbi, sizeof(mbi));

        fout << "MEMORY_BASIC_INFORMATION:  " << std::endl;
        fout << " - PVOID  BaseAddress (hex)      0x" << std::hex << std::uppercase << mbi.BaseAddress << std::endl;
        fout << " - DWORD  AllocationProtect        " << mbi.AllocationProtect << std::endl;
        fout << " - SIZE_T RegionSize (hex)       0x" << std::hex << std::uppercase << mbi.RegionSize << std::endl;
        fout << " - DWORD  State (text)             " << mbi.State << std::endl;
        fout << " - DWORD  Protect (text)           " << mbi.Protect << std::endl;
        fout << " - DWORD  Type (text)              " << mbi.Type << "\n" << std::endl;

        ////fout << "VirtualQuery   " << buf << std::endl;
        fout << "ByteIterator   " << ByteIterator << std::endl;
        fout << "ByteIterator 0x" << std::hex << ByteIterator << std::endl;

        // If first byte of signature is equal to current byte, we may have a pattern.
        // (e.g.: FirstSigByte: "4d", CurrentByte(): "4d" 
        if (FirstSigByte.compare(CurrentByte()) == 0)
        {
            fout << "Match:   "<< std::endl;
            fout << "  - FirstSigByte  0x" << std::hex << FirstSigByte << std::endl;
            fout << "  - CurrentByte() 0x" << std::hex << CurrentByte() << std::endl;

            fout << "SequenceIterator:   " << std::endl;

            // We compare pair-wise, so we only need half of the iterations
            for (SequenceIterator = 0; SequenceIterator < (Sig.length() / 2); SequenceIterator++)
            {
                //Sleep(10);
                //std::cout << "CurrentByte(): " << std::hex << CurrentByte() << std::endl;
                fout << "  - SequenceIterator   " << SequenceIterator << std::endl;
                fout << "  - SequenceIterator 0x" << std::hex << SequenceIterator << std::endl;
                fout << "  - Sig.substr(SequenceIterator * 2, 2)" << Sig.substr(SequenceIterator * 2, 2) << std::endl;
                fout << "  - CurrentByte()" << CurrentByte() << std::endl;

                //Sleep(5000);
                if (Sig.substr(SequenceIterator * 2, 2).compare("??") == 0) 
                {
                    Buffer.append("??");
                    //std::cout << "Buffer: " << Buffer << std::endl;
                }
                // Success if the next byte in signature is equal to current byte
                else if (Sig.substr(SequenceIterator * 2, 2).compare(CurrentByte()) == 0)
                {
                   Buffer.append(CurrentByte());
                }
                else
                {
                    // No match anyway, clear buffer and reset

                    //std::cout << "Clear buffer" << std::endl;
                    Buffer.clear();
                    break;
                }
            }

            // If mask and buffer are equal (e.g.: "4d??90" == "4d??90" 
            if (Sig.compare(Buffer) == 0)
            {
                Container.insert(std::pair<int, std::string>(ByteIterator+SequenceIterator, Buffer));
                Buffer.clear();

                // If we are fine with stopping when one signature is found, break loop.
                if (!fullscan) {
                    break;
                }
            }
            fout.close();
            //std::cout << std::endl;
        }
    }
 
    std::cout << "[+] Scan complete..." << std::endl;
    PrintContainer();
    //Sleep(10000);
}
