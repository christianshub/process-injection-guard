#include "SigScan.h"
#include <string>     // std::string, std::stol
#include "windows.h"

std::string Sig = "";                       // full or masked signature: e.g.: "4d5a90"/"4d??90"
std::string FirstSigByte = "";              // we start by comparing each byte with the signature's initial bytes.
std::string Buffer = "";                    // holds the signature found byte by byte.

unsigned int ByteIterator = 0;              // is iterating over all bytes.
unsigned int SequenceIterator = 0;          // is starting to iterate when the initial byte signature is found.

std::map<int, std::string> Container = {};  // will be used if "fullscan" is enabled. In case there are more signatures.


void SigScan::PrintContainer(std::ostream& out)
{
    if (Container.size() != 0)
    {
        out << "[+] Signature found:" << std::endl;
        std::cout << "[+] Signature found:" << std::endl;
        for (auto& x : Container)
        {
            out << "[+] [ Address: " << std::uppercase << std::hex << std::setw(8) << std::setfill('0') << x.first << " | Signature: " << x.second << " ]" << std::endl;
            std::cout << "[+] [ Address: " << std::uppercase << std::hex << std::setw(8) << std::setfill('0') << x.first << " | Signature: " << x.second << " ]" << std::endl;
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

std::string SigScan::CurrentByte()
{
    return hexStr((PBYTE)(ByteIterator + SequenceIterator), 1);
}

// Converts bytes to a readable string (hex representation).
std::string SigScan::hexStr(BYTE* data, int len)
{
    std::stringstream ss;
    ss << std::hex;

    for (int i = 0; i < len; ++i)
        ss << std::setw(2) << std::setfill('0') << (int)data[i];

    return ss.str();
}


// public
void SigScan::FindSignature(std::string signature, unsigned int address, ULONG size, std::ostream& out)
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
