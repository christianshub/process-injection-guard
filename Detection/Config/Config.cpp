#include "Config.h"

std::string GetDesktopPath() {

	CHAR path[MAX_PATH];
	HRESULT hRes = SHGetFolderPathA(NULL, CSIDL_DESKTOP, 0, NULL, path);

	if (SUCCEEDED(hRes))
	{
		return (std::string(path) + "\\");
	}
	return "Couldn't retrieve desktop path\n";
}

//std::string GetDesktopPath() {
//
//	TCHAR path[MAX_PATH];
//	HRESULT hRes = SHGetFolderPath(NULL, CSIDL_DESKTOP, 0, NULL, path);
//
//	if (SUCCEEDED(hRes))
//	{
//		std::wstring wstr = path;
//		return (std::string(WSTRING_TO_STRING(wstr)) + "\\");
//	}
//	std::cerr << "Couldn't retrieve desktop path\n";
//}

std::string EraseAllSubStr(std::string& mainStr, const std::string& toErase)
{
	size_t pos = std::string::npos;

	// Search for the substring in string in a loop untill nothing is found
	while ((pos = mainStr.find(toErase)) != std::string::npos)
	{
		// If found then erase it from string
		mainStr.erase(pos, toErase.length());
	}

	return mainStr;
}

std::string stripFilename(std::string& fname)
{
	EraseAllSubStr(fname, "\\");
	EraseAllSubStr(fname, "/");
	EraseAllSubStr(fname, ".ini");
	EraseAllSubStr(fname, ".exe");
	EraseAllSubStr(fname, ".txt");
	EraseAllSubStr(fname, ".cfg");

	return fname;
}

std::string CreateFolder(std::string path, std::string folderName)
{
	path += folderName + '\\';
	
	CreateDirectoryA(path.c_str(), NULL);

	return path;
}

bool VerifyConfig(std::string filepath, std::vector<std::string> content)
{
	bool integrityAccepted = true;

	std::ifstream test(filepath);

	//int count = 0;
	//std::string line;
	//while (std::getline(test, line))
	//{
	//	if (line.find(content[count]) != std::string::npos) {
	//		integrityAccepted = true;
	//	}
	//	else
	//	{
	//		integrityAccepted = false;
	//		break;
	//	}
	//	count++;
	//}

	if (!test)
	{
		std::cout << "Creating folder and config..." << std::endl;
		std::ofstream outfile(filepath);
		for (unsigned int i = 0; i < content.size(); i++)
		{
			outfile << content[i] << std::endl;
		}
		integrityAccepted = false;
		outfile.close();
	}

	return integrityAccepted;
}

std::string VerifyINI(std::string cfgFolderName, std::string cfgName, std::vector<std::string> cfgContent)
{
	std::string configPath = CreateFolder(GetDesktopPath(), cfgFolderName);

	stripFilename(cfgName);

	std::string filepath = configPath + cfgName + ".ini";

	VerifyConfig(filepath, cfgContent);

	return filepath;
}

std::string ReadKey(const std::string appName, const std::string keyName, std::string filePath)
{
	char buffer[MAX_PATH];
	GetPrivateProfileStringA(appName.c_str(), keyName.c_str(), NULL, buffer, MAX_PATH, filePath.c_str());

	std::string content(buffer);

	std::ifstream test(filePath);
	if (!test)
	{
		std::cout << "No such file." << std::endl;
	}

	return std::string(content);
}
