#include <iostream>
#include <fstream>
#include "../Detection/SigScanner/SigScanner.h"

int main()
{
    //open file
    std::ifstream infile("MyFile.txt");

    //get length of file
    infile.seekg(0, std::ios::end);
    size_t length = infile.tellg();
    infile.seekg(0, std::ios::beg);

    char buffer[10000];
    // don't overflow the buffer!
    if (length > sizeof(buffer))
    {
        length = sizeof(buffer);
    }

    //read file
    infile.read(buffer, length);

    std::map<int, std::string> Container = FindSignature("74", (unsigned int) &buffer, 10000);

    //if (Container.size() == 2)
    //{
    //    std::cout << std::endl;
    //    for (auto& x : Container)
    //    {
    //        std::cout << "[SIGNATURE FOUND] [ Address: " << std::uppercase << std::hex << std::setw(8) << std::setfill('0') << x.first << " | Signature: " << x.second << " ]" << std::endl;
    //    }
    //    std::cout << std::endl;
    //}


}