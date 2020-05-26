#include "DumpOutput.h"
#include "Convertions.h"

void DumpOutput::WriteOutput(std::string message, int input)
{
	//TCHAR NPath[MAX_PATH];
	//GetCurrentDirectory(MAX_PATH, NPath);

	std::string fname = "C:\\Users\\Work\\Desktop\\file.txt";
	std::ofstream fout(fname);

	//std::cout << NPath << std::endl;
	fout << message << input << std::endl;
	fout.close();
}


//TCHAR NPath[MAX_PATH];
//GetCurrentDirectory(MAX_PATH, NPath);