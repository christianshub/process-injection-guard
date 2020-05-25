#pragma once
#include "../Trampoline.h"
#include "../Utility.h"

class kernelHook {

	typedef HMODULE(__stdcall* prototype) (LPCSTR fileName);
	static prototype original;
	static HMODULE __stdcall HookFun(LPCSTR fileName);

public:

	static std::string detectedPath;
	static void InitLoadLibHook();

};
