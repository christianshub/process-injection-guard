#include "ntdllHook.h"

std::string ntdllHook::detectedPath = "";
ntdllHook::prototype ntdllHook::original = nullptr;

BOOL __stdcall ntdllHook::HookFun(PCWSTR FileName, ULONG Size, PWSTR Buffer, PWSTR* ShortName) {

	std::cout << "\n[!] RtlGetFullPathName_U call detected!" << std::endl;
	std::wcout << "[!] Intruder path: " << FileName << "\n" << std::endl;

	detectedPath = HookLib::TO_STRING(FileName);

	return ntdllHook::original(FileName, Size, Buffer, ShortName);
}

void ntdllHook::InitRtlPathHook()
{
	std::cout << "[+] Initiating hook for: RtlGetFullPathName_U" << std::endl;

	HMODULE hModule = LoadLibraryA("ntdll.dll");

	prototype origFunAddr = (prototype) GetProcAddress(hModule, "RtlGetFullPathName_U");

	original = (prototype)(HookLib::Trampoline( (PBYTE) origFunAddr, (PBYTE) HookFun, 5));
}
