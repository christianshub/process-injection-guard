#include "SigScan/SigScan.h"
#include "SigScan/ScanHiddenModules/ScanHiddenModules.h"
#include "SigScan/ScanModules/ScanModules.h"
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
            std::cout << "1 pressed: Scan modules\n" << std::endl;
            //ScanModules::Find("3d3d3d3d3d????696d706c65", 1);
            ScanModules::Find("4d5a", 1);
        }

        //if (GetAsyncKeyState(0x32) & 1)
        //{
        //    std::cout << "2 pressed: Scan specific module\n" << std::endl;
        //    ScanModules::Find("3d3d3d3d3d????696d706c65", "SimplePayload.dll", 1);
        //}

        //if (GetAsyncKeyState(0x33) & 1)
        //{
        //    std::cout << "3 pressed: Scan hidden modules\n" << std::endl;
        //    ScanHiddenModules::Find("3d3d3d3d3d????696d706c65", true);
        //}
        

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
