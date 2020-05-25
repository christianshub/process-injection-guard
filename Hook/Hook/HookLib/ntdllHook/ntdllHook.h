#pragma once

#include "../Trampoline.h"
#include "../Utility.h"

class ntdllHook {

	typedef ULONG(__stdcall* prototype)(PCWSTR FileName, ULONG Size, PWSTR Buffer, PWSTR* ShortName);
	static prototype original;
	static BOOL __stdcall HookFun(PCWSTR FileName, ULONG Size, PWSTR Buffer, PWSTR* ShortName);

public:

	static std::string detectedPath;
	static void InitRtlPathHook();

};
