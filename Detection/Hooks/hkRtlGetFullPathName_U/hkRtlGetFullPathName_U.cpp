#include "hkRtlGetFullPathName_U.h"

RtlPrototype RtlOriginal = nullptr;

BOOL __stdcall RtlHook(PCWSTR FileName, ULONG Size, PWSTR Buffer, PWSTR* ShortName) {

	std::cout << "\n[HOOK] RtlGetFullPathName_U call detected!" << std::endl;
	std::wcout << "[HOOK] Intruder path: " << FileName << std::endl;

	return RtlOriginal(FileName, Size, Buffer, ShortName);
}

void InitRtlPathHook()
{
	std::cout << "[+] Initiated hook for: RtlGetFullPathName_U" << std::endl;

	HMODULE hModule = LoadLibraryA("ntdll.dll");

	RtlPrototype origFunAddr = (RtlPrototype) GetProcAddress(hModule, "RtlGetFullPathName_U");

	RtlOriginal = (RtlPrototype)(Trampoline( (PBYTE) origFunAddr, (PBYTE) RtlHook, 5));
}
