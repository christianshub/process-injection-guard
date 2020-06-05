#pragma once

#include <windows.h>
#include <iostream>
#include <vector>
#include <sstream>
#include <algorithm>

/// <summary>
/// Replaces upper case letters to lower case
/// </summary>
std::string ToLowercase(std::string& str);

/// <summary>
/// Replaces all substrings in a string
/// </summary>
std::string ReplaceAllSubStr(std::string& mainStr, std::string toBeReplaced, std::string replaceWith);

/// <summary>
/// Stores comma seperated string into vector of signatures
/// </summary>
/// <param name="signatures">Valid signatures: "3BDE", "3B DE",  "3bde" or "3bde" (Invalid: "\x31\xF6")</param>
std::vector<std::string> ParseSignatures(const std::string signatures);

unsigned int ParseNumerics(const std::string num);

/// <summary>
/// 
/// </summary>
std::vector<std::string> ParseModuleNames(const std::string modulenames);
