#include <iostream>
#include <algorithm> // std::transform
#include <string>    // std::tolower

/// <summary>
/// Replaces upper case letters to lower case
/// </summary>
std::string ToLowercase(std::string& str);

/// <summary>
/// Strips all substrings from string
/// </summary>
std::string EraseAllSubStr(std::string& mainStr, const std::string& toErase);

/// <summary>
/// Replaces all substrings in a string
/// </summary>
std::string ReplaceAllSubStr(std::string& mainStr, std::string toBeReplaced, std::string replaceWith);
