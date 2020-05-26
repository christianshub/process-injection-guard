#include "SigScan/SigScan.h"
#include "SigScan/Scan/Scan.h"
#include <windows.h>
#include <iostream>

DWORD WINAPI Sigscanner(HMODULE hModule)
{
    //Create Console
    AllocConsole();
    FILE* f;
    freopen_s(&f, "CONOUT$", "w", stdout);

    std::cout << "\n======= Signature Scanner ========" << std::endl;
    std::cout << "VK_NUMPAD4:     Get loaded modules  " << std::endl;
    std::cout << "1:              Scan modules"         << std::endl;
    std::cout << "2:              Scan specific module" << std::endl;
    std::cout << "3:              Scan hidden modules"  << std::endl;
    std::cout << "VK_END:         Detach              " << std::endl;
    std::cout << "====================================\n" << std::endl;

    while (true)
    {
        if (GetAsyncKeyState(VK_END) & 1)
        {
            break;
        }

        if (GetAsyncKeyState(0x31) & 1)
        {
            std::cout << "1 pressed: Scan all modules\n" << std::endl;
            Scan::ModMemory("6861636b", "ALL", "C:\\Users\\Laptop\\Desktop"); // 6861636b == hack == internalHack.dll
        }

        if (GetAsyncKeyState(0x32) & 1)
        {
            std::cout << "2 pressed: Scan specific module\n" << std::endl;
            Scan::ModMemory("6861636b", "InternalHack.dll", "C:\\Users\\Laptop\\Desktop");
        }

        if (GetAsyncKeyState(0x33) & 1)
        {
            std::cout << "3 pressed: Scan PRIVATE and PAGE_EXECUTE_READWRITE Memory\n" << std::endl;
            Scan::PrivateERW("6861636b", "C:\\Users\\Laptop\\Desktop");
        }
        

        Sleep(10);
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
        CloseHandle(CreateThread(0, 0, (LPTHREAD_START_ROUTINE)Sigscanner, hModule, 0, 0));
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
