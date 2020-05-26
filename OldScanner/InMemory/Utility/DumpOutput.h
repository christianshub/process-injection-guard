#pragma once
#include <windows.h>
#include <iostream>
#include <fstream>
#include <string.h>

class DumpOutput
{
public:
	static void WriteOutput(std::string message, int input);
	//std::string path = NPath;
	//std::string fpath = path + "\\Dump";
};

