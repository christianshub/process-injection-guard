#pragma once

#include <iostream>
#include <windows.h>
#include <sstream>
#include <iomanip>
#include <string>
#include <clocale>
#include <locale>
#include <vector>

namespace HookLib {
	BYTE* Trampoline(PBYTE src, PBYTE dst, const uintptr_t len);
};

