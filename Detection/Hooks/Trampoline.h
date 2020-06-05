#pragma once

#include <iostream>
#include <windows.h>

/// <summary>
/// 
/// </summary>
/// <param name="src"></param>
/// <param name="dst"></param>
/// <param name="len">length of </param>
/// <returns></returns>
BYTE* Trampoline(PBYTE src, PBYTE dst, const uintptr_t len);

