#include "SigScan.h"

// Converts bytes to a readable string (hex representation).
std::string SigScan::hexStr(BYTE* data, int len)
{
    std::stringstream ss;
    ss << std::hex;

    for (int i = 0; i < len; ++i)
        ss << std::setw(2) << std::setfill('0') << (int)data[i];

    return ss.str();
}

// Read file
void SigScan::ReadFile()
{
    std::ifstream File(DllFile, std::ios::binary | std::ios::ate);

    auto FileSize = File.tellg();

    fileSize = (unsigned int)FileSize;

    byteData = new BYTE[static_cast<UINT_PTR>(FileSize)];

    File.seekg(0, std::ios::beg);
    File.read(reinterpret_cast<char*>(byteData), FileSize);
    File.close();
}

// public:
void SigScan::FindSignature(std::string Sig, std::string Mask, bool fullscan)
{
    std::cout << "\n[+] Scanning for signatures..." << std::endl;

    FirstSigByte = Sig.substr(0, 2); // Get the first byte from Sig.
    Dictionary.clear();              // Clear the dictionary for patterns before initiation.

    for (ByteIterator = 0; ByteIterator < fileSize; ByteIterator++)
    {
        CountAddress(ByteIterator); // Counts every 16th byte

        // If first byte of signature is equal to current byte, we may have a pattern.
        // (e.g.: FirstSigByte: "4d", CurrentByte(): "4d" 
        if (FirstSigByte.compare(CurrentByte()) == 0)
        {
            // We compare pair-wise, so we only need half of the iterations
            for (SequenceIterator = 0; SequenceIterator < (Sig.length() / 2); SequenceIterator++)
            {
                // Success if the next byte in signature is equal to current byte
                if (Sig.substr(SequenceIterator * 2, 2).compare(CurrentByte()) == 0)
                {
                    // Append "??" if it's mask
                    if (Mask.substr(SequenceIterator * 2, 2).compare("??") == 0)
                    {
                        Buffer.append("??");
                    }
                    // Append CurrentByte if it's not a mask.
                    else
                    {
                        Buffer.append(CurrentByte());
                    }
                }
                else
                {
                    // No match anyway, clear buffer and reset
                    Buffer.clear();
                    break;
                }
            }

            // If mask and buffer are equal (e.g.: "4d??90" == "4d??90" 
            if (Mask.compare(Buffer) == 0)
            {
                // If we want to find all patterns
                if (fullscan)
                {
                    // Appends address and buffer (holding the signature), then clear buffer and continue.
                    Dictionary.insert(std::pair<int, std::string>(currentAddress, Buffer));
                    Buffer.clear();
                }
                else
                {
                    // If we are fine with stopping when one signature is found, break loop.
                    break;
                }
            }
        }
    }
    std::cout << "[+] Scan complete..." << std::endl;

    PrintDictionary();
}
