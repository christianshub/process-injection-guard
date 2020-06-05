#include "StrManipulation.h"

std::string ToLowercase(std::string& str)
{
	std::transform(str.begin(), str.end(), str.begin(),
		[](unsigned char c) { return std::tolower(c); });

	return str;
}

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

std::string ReplaceAllSubStr(std::string& mainStr, const std::string toBeReplaced, const std::string replaceWith)
{
	size_t pos = std::string::npos;
	while ((pos = mainStr.find(toBeReplaced)) != std::string::npos)
	{
		mainStr.replace(pos, toBeReplaced.length(), replaceWith);
	}

	return mainStr;
}