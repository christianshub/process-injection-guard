#pragma once

#include <iostream>
#include <windows.h>
#include <sstream>
#include <iomanip>
#include <string>
#include <clocale>
#include <locale>
#include <vector>

std::string INT_TO_HEXSTRING(int input);
std::string PCWSTR_TO_STRING(PCWSTR string);
std::string PBYTE_TO_HEXSTR(PBYTE data, int len);
std::string WSTRING_TO_STRING(std::wstring internal);

char* PWCHAR_T_TO_PCHAR(wchar_t* string);
