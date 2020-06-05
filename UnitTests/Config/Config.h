#pragma once
#include <iostream>
#include <Windows.h>
#include <fstream>
#include <shlobj.h>
#include <algorithm>
#include <vector>

/// <summary>
/// Gets desktop path
/// </summary>
/// <returns>C:\Users\USER\Desktop\</returns>
std::string GetDesktopPath();

/// <summary>
/// Strips all substrings from string
/// </summary>
std::string EraseAllSubStr(std::string& mainStr, const std::string& toErase);

/// <summary>
/// Strips filename from known file endings and backslashes
/// </summary>
std::string stripFilename(std::string& fname);

/// <summary>
/// Create folder and return full path to folder
/// </summary>
std::string CreateFolder(std::string path, std::string folderName);


/// <summary>
/// Writes needed config information
/// </summary>
bool VerifyConfig(std::string filepath, std::vector<std::string> content);

/// <summary>
/// Verifies a config folder and file on the desktop
/// is created, if not, we create one.
/// Standard: 
///		- Config, 
///		- config.ini, 
///		- config.ini's content: "[Config]", "Signature="
/// </summary>
/// <returns>filepath</returns>
std::string VerifyINI(std::string cfgFolderName = "Config", std::string cfgName = "config.ini", std::vector<std::string> cfgContent = { "[AppName]", "KeyName=" });

/// <summary>
/// Get the content of a certain key in an .ini file
/// source: https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getprivateprofilestringa
/// </summary>
/// <param name="appName">The name of the config file, e.g.:  [Config]</param>
/// <param name="keyName">A key corrosponds to a field, e.g.: keyName=TextGoesHere</param>
/// <returns>Content of .ini file</returns>
std::string ReadKey(const std::string appName, const std::string keyName, std::string filePath);
