#include "gtest/gtest.h"
#include "SigScanner/SigScanner.h"
#include "Hooks/Trampoline.h"
#include <fstream>

/* 
    Finding signature "74" (ASCII: t)
        - Searching through file containing the word 'test'
        - Should find 2 matches.
*/
TEST(Signatures, TestSigs) {

    //open file
    std::ifstream infile("TestFiles//test1.txt");

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

/*
    Finding signature "73 74 72 ?? 6e 67" (ASCII: str??ng)
        - Searching through file containing the word 'test'
        - Should find 2 matches.
*/
TEST(Signatures, TestMask) {

    //open file
    std::ifstream infile("TestFiles//test2.txt");

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

    std::map<int, std::string> container = FindSignature("737472??6e67", (unsigned int)&buffer, 10000);

    ASSERT_EQ(container.size(), 2);

    EXPECT_TRUE(true);
}

/*
    We will test CurrentBytes that iterates over each byte
    in the signature function.

    We print 'string' to bytes (73 74 72 69 6e 67).
*/
TEST(Signatures, TestCurrentByte) {

    //open file
    std::ifstream infile("TestFiles//test3.txt");

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

    std::vector<std::string> bytes = { "73", "74", "72", "69", "6e", "67" };
    for (int i = 0; i < 5; i++) {
        ASSERT_EQ(CurrentByte((unsigned int)&buffer + i), bytes[i]);
    }

    EXPECT_TRUE(true);
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    RUN_ALL_TESTS();
    getchar();
}