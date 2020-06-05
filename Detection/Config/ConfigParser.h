#pragma once

#include <windows.h>
#include <iostream>
#include <vector>
#include <sstream>
#include "../Utility/StrManipulation.h"

/// <summary>
/// Stores a comma seperated string into vector of signatures
/// </summary>
/// <param name="signatures">Valid signatures: "3BDE", "3B DE",  "3bde" or "3bde" (Invalid: "\x31\xF6")</param>
std::vector<std::string> ParseSignatures(const std::string signatures);

/// <summary>
/// Parses 0/1 input, or if no input is given
/// </summary>
unsigned int ParseNumerics(const std::string num);

/// <summary>
/// Removes spaces etc.
/// </summary>
std::vector<std::string> ParseModuleNames(const std::string modulenames);
