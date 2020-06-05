#include "hkLoadLibraryA.h"

prototype original = nullptr;

HMODULE __stdcall LoadLibHook(LPCSTR FileName) {


	std::cout << "\n[HOOK] LoadLibraryA call detected!" << std::endl;
	std::cout << "[HOOK] Intruder path: " << FileName << std::endl;
	
	return original(FileName);
}

void InitLoadLibHook()
{
	std::cout << "[+] Initiated hook for: LoadLibraryA" << std::endl;

	HMODULE hModule = LoadLibraryA("kernel32.dll");

	prototype origFunAddr = (prototype)GetProcAddress(hModule, "LoadLibraryA");

	original = (prototype)(Trampoline((PBYTE)origFunAddr, (PBYTE) LoadLibHook, 5));
}
