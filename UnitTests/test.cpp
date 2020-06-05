#include "SigScanner/SigScanner.h"
#include "gtest/gtest.h"
#include <fstream>

/* 
    Finding signature "74" (ASCII: t)
        - Searching through file containing the word 'test'
        - Should find 2 matches.
*/
TEST(Signatures, TestFor74) {

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

    std::map<int, std::string> container = FindSignature("74", (unsigned int)&buffer, 10000);

    ASSERT_EQ(container.size(), 2);
   
	EXPECT_TRUE(true);
}


int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    RUN_ALL_TESTS();
    getchar();
}