#pragma once

#include <iostream>
#include <windows.h>
#include <sstream>
#include <iomanip>
#include <string>
#include <clocale>
#include <locale>
#include <vector>


std::string TO_STRING(PCWSTR string);
std::string hexStr(PBYTE data, int len);

char* TO_CHAR(wchar_t* string);

