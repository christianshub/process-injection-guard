#include <iostream>
#include "SigScan/SigScan.h"


int HexToDec(int hex) {
    unsigned int x;
    std::stringstream ss;
    ss << std::hex << std::to_string(hex);
    ss >> x;
    return x;
}

int main()
{
    //SigScan scan("C:\\ac.dll");

    ////signature: assaultcube hack (ASCII)
    //scan.FindSignature("61737361756c7463756265206861636b", "61737361756c7463756265206861636b", true);

    int y = 1000;



    std::cout << "x " << HexToDec(y) << std::endl;
    //int convertdata = static_cast<int>(data);
    //std::cout << "data" << convertdata << std::endl;
}

// 53 69 6D 70 6C 65 // Simple