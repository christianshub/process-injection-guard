#pragma once
#include "../Trampoline.h"


typedef HMODULE(__stdcall* prototype) (LPCSTR fileName);
HMODULE __stdcall LoadLibHook(LPCSTR fileName);

void InitLoadLibHook();
