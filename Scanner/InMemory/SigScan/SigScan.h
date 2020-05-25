#pragma once

#include <windows.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <map>
#include <vector>
#include "../Utility/Convertions.h"

namespace SigScan {

    /// <summary>
    /// Helper functions
    /// </summary>
    std::string hexStr(BYTE*, int);

    /// <summary>
    /// Reads binary data byte by byte. 
    /// </summary>
    /// <returns> Returns the current byte as a string (hex) </returns>
    std::string CurrentByte();

    /// <summary>
    /// Prints the final results
    /// </summary>
    void PrintContainer(std::ostream& out);


    /// <summary>
    /// Scans for signatures from within a memory's address space.
    /// </summary>
    /// <param name="signature"> full or masked signature: e.g.: "4d5a90"/"4d??90" </param>
    /// <param name="beginning"> start address                                     </param>
    /// <param name="size">      scan size                                         </param>
    /// <param name="fullScan">  keep scanning even if one signature is found      </param>
    void FindSignature(std::string signature, unsigned int address, ULONG size, std::ostream& out);
}

