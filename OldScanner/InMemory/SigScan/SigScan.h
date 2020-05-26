#pragma once

#include <windows.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <map>
#include <vector>
#include "../Utility/ConsoleColors.h"

class SigScan {

    static std::string Sig;                        // full or masked signature: e.g.: "4d5a90"/"4d??90"
    static std::string FirstSigByte;               // we start by comparing each byte with the signature's initial bytes.
    static std::string Buffer;                     // holds the signature found byte by byte.

    static long long ByteIterator;              // is iterating over all bytes.
    static long long SequenceIterator;          // is starting to iterate when the initial byte signature is found.

    static std::map<int, std::string> Container;   // will be used if "fullscan" is enabled. In case there are more signatures.

    /// <summary>
    /// Helper functions
    /// </summary>
    static std::string hexStr(BYTE*, int);

    /// <summary>
    /// Reads binary data byte by byte. 
    /// </summary>
    /// <returns> Returns the current byte as a string (hex) </returns>
    static std::string CurrentByte() {
        return hexStr((PBYTE)(ByteIterator + SequenceIterator), 1);
    }

public:

    //ConsoleColors color;

    /// <summary>
    /// Prints the final results
    /// </summary>
    static void PrintContainer() {
        if (Container.size() != 0)
        {
            //color.SetColor(Green);
            std::cout << "[+] Signature found:" << std::endl;
            for (auto& x : Container)
            {
                std::cout << "[+] [ Address: " << std::uppercase << std::hex << std::setw(8) << std::setfill('0') << x.first << " | Signature: " << x.second << " ]" << std::endl;
            }
            std::cout << std::endl;
        }
        else
        {
            //color.SetColor(Red);
            std::cout << "[-] No signatures found.\n" << std::endl;
        }
        //color.SetColor(White);
    }
    
    /// <summary>
    /// Scans for signatures from within a memory's address space.
    /// </summary>
    /// <param name="signature"> full or masked signature: e.g.: "4d5a90"/"4d??90" </param>
    /// <param name="beginning"> start address                                     </param>
    /// <param name="size">      scan size                                         </param>
    /// <param name="fullScan">  keep scanning even if one signature is found      </param>
    static void FindSignature(std::string signature, unsigned int beginning, ULONG size, bool fullScan);

};
