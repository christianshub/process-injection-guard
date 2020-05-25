#include "Trampoline.h"

BYTE* HookLib::Trampoline(PBYTE source, PBYTE destination, const uintptr_t byteLen)
{
	if (byteLen < 5) {
		std::cout << "[-] Trampoline Hook Activation: FAILED" << std::endl;
		std::cout << "[-] REASON: Need atleast 5 bytes to call or jump address" << std::endl;
		return 0;
	}

	BYTE* trampoline = (BYTE*)VirtualAlloc(0, byteLen, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	memcpy_s(trampoline, byteLen, source, byteLen);

	uintptr_t trampolineRVA = source - trampoline - byteLen;

	*(trampoline + byteLen) = 0xE9;

	*(uintptr_t*)((uintptr_t)trampoline + byteLen + 1) = trampolineRVA;

	DWORD currentProtection;
	VirtualProtect(source, byteLen, PAGE_EXECUTE_READWRITE, &currentProtection);

	uintptr_t relativeAddress = destination - source - byteLen;

	*source = 0xE9;

	*(uintptr_t*)(source + 1) = relativeAddress;

	VirtualProtect(source, byteLen, currentProtection, &currentProtection);

	return trampoline;
}


