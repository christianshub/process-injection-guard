#pragma once

#include <windows.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <map>
#include <vector>

class SigScan {


public:

    SigScan(std::string InDllFile) : DllFile(InDllFile)
    {
        ReadFile(); // read file from dll path and store binary data in 'byteData'
    }

    void PrintDictionary() {

        //if (Dictionary.size() != 0)
        //{
        std::cout << "\n[+] Signature(s) found in file " << DllFile << ":\n" << std::endl;
        for (auto& x : Dictionary)
        {
            std::cout << "[ Address: " << std::uppercase << std::hex << std::setw(8) << std::setfill('0') << x.first << " | Signature: " << x.second << " ]" << std::endl;
        }
        //}
        //else
        //{
        //    std::cout << "\n[-] NO SIGNATURES FOUND\n" << std::endl;
        //}
    }

    void FindSignature(std::string, std::string, bool);

private:
    std::string DllFile;                    // path to dll file. e.g.: "C:\\File.dll"
    std::string Sig;                        // full signature: e.g.: "4d5a90"
    std::string Mask;                       // full signature incl. mask: e.g.: "4d??90"
    std::string FirstSigByte;               // we start by comparing each byte with the signature's initial bytes.
    std::string Buffer;                     // holds the signature found byte by byte.

    unsigned int ByteIterator;              // is iterating over all bytes.
    unsigned int SequenceIterator;          // is starting to iterate when the initial byte signature is found.
    unsigned int currentAddress;            // the current address of where the currentByte is at.
    unsigned int fileSize;

    BYTE* byteData;                         // contains the binary data

    std::map<int, std::string> Dictionary;  // will be used if "fullscan" is enabled. In case there are more signatures.


    // Convert byte data to readable string (hex)
    std::string hexStr(BYTE*, int);
    //std::string hexStr(std::map<BYTE*, int> data);

    // Reads binary data byte by byte. 
    std::string CurrentByte() {
        // Wrapper around hexStr, which can otherwise also be used to print
        //  - i and j are adjusting the placement (see the function 'FindSignature').
        return hexStr(byteData + ByteIterator + SequenceIterator, 1);
    }

    // Bytes per row. We count for every 16th bytes
    void CountAddress(unsigned int count)
    {
        if (count % 16 == 0) {
            currentAddress = count;
        }
    }

    // Print address in uppercase hex format with 8 digits.
    void PrintCurrentAddress() {
        std::cout << std::uppercase << std::hex << std::setw(8) << std::setfill('0') << currentAddress << std::endl;
    }

    // Read file
    void ReadFile();
};
