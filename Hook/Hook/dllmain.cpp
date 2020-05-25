#include "HookLib/kernel32Hook/kernel32Hook.h"
#include "HookLib/ntdllHook/ntdllHook.h"

DWORD WINAPI Hook(HMODULE hModule)
{
    //Create Console
    AllocConsole();
    FILE* f;
    freopen_s(&f, "CONOUT$", "w", stdout);

    std::cout << "\n===== Hook detection =====\n";
    std::cout << "VK_END:     Detach \n\n" << std::endl;

    // Initite RtlGetFullPathName_U first or LoadLibraryHook will catch the initiation.
    ntdllHook::InitRtlPathHook();
    kernelHook::InitLoadLibHook();

    while (true)
    {
        if (GetAsyncKeyState(VK_END) & 1)
        {
            break;
        }
        Sleep(5000);
    }

    fclose(f);
    FreeConsole();
    FreeLibraryAndExitThread(hModule, 0);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        CloseHandle(CreateThread(0, 0, (LPTHREAD_START_ROUTINE)Hook, hModule, 0, 0));
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
