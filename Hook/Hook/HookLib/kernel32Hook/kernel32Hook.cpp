#include "kernel32Hook.h"

std::string kernelHook::detectedPath = "";

kernelHook::prototype kernelHook::original = nullptr;

HMODULE __stdcall kernelHook::HookFun(LPCSTR FileName) {


	std::cout << "\n[!] LoadLibraryA call detected!" << std::endl;
	std::cout << "[!] Intruder path: " << FileName << "\n" << std::endl;

	detectedPath = FileName;
	
	return original(FileName);
}

void kernelHook::InitLoadLibHook()
{
	std::cout << "[+] Initiating hook for: LoadLibraryA" << std::endl;

	HMODULE hModule = LoadLibraryA("kernel32.dll");

	prototype origFunAddr = (prototype)GetProcAddress(hModule, "LoadLibraryA");

	original = (prototype)(HookLib::Trampoline((PBYTE)origFunAddr, (PBYTE) HookFun, 5));
}
