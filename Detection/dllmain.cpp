#include <windows.h>
#include <iostream>

#include "Hooks/hkLoadLibraryA/hkLoadLibraryA.h"
#include "Hooks/hkRtlGetFullPathName_U/hkRtlGetFullPathName_U.h"

#include "SigScanner/SigScanner.h"
#include "Config/Config.h"
#include "Config/ConfigParser.h"
#include "Utility/Keys.h"

DWORD WINAPI Detection(HMODULE hModule)
{
    // Create Console
    AllocConsole();
    FILE* f;
    freopen_s(&f, "CONOUT$", "w", stdout);

    // Scan
    std::string filePath = VerifyINI("Detection", "config.ini", { "[Config]", "Signature=", "Module=",  "AutoHook=", "AutoScan=" });
    std::string sigContent = ReadKey("Config", "Signature", filePath);
    std::vector<std::string> signatures = ParseSignatures(sigContent);

    unsigned int AutoHook = ParseNumerics(ReadKey("Config", "AutoHook", filePath));
    unsigned int AutoScan = ParseNumerics(ReadKey("Config", "AutoScan", filePath));

    std::cout << "\n=====================  DETECTION MODULE INJECTED  ====================" << std::endl;
    std::cout << "Press '1'         Hook RtlGetFullPathName_U hook" << std::endl;
    std::cout << "Press '2'         Hook LoadLibraryA hook" << "\n" << std::endl;

    std::cout << "Press '3'         Scan module(s) from config.ini" << std::endl;
    std::cout << "Press '4'         Scan known Reflective DLL memory regions" << std::endl;
    std::cout << "Press '5'         Scan all memory regions" << "\n" << std::endl;

    std::cout << "Press '0'         Detach Detection module" << std::endl;
    std::cout << "======================================================================" << "\n" << std::endl;

    while (true)
    {

        if (AutoHook) 
        {
            std::cout << "**************              AUTOHOOK: ON             ****************\n" << std::endl;
            InitRtlPathHook();
            InitLoadLibHook();
            AutoHook = 0;
            Sleep(5000);
        }

        if (AutoScan)
        {
            std::cout << "\n**************              AUTOSCAN: ON             ****************\n" << std::endl;

            std::cout << "SCANNING MODULE(S)" << std::endl;
            for (size_t i = 0; i < signatures.size(); i++)
            {
                ModuleScan(signatures[i]);
            }

            std::cout << "\nSCANNING FOR REFLECTIVE DLL(S)" << std::endl;
            for (size_t i = 0; i < signatures.size(); i++)
            {
                ManualMapScan(signatures[i]);
            }

            AutoScan = 0;
        }

        if (GetAsyncKeyState(KeyPress::VK_1) & 1)
        {
            std::cout << "\n**************     HOOKING RtlGetFullPathName_U     ****************\n" << std::endl;
            InitRtlPathHook();
        }

        if (GetAsyncKeyState(KeyPress::VK_2) & 1)
        {
            std::cout << "\n**************         HOOKING LoadLibraryA         ****************\n" << std::endl;

            InitLoadLibHook();
        }

        if (GetAsyncKeyState(KeyPress::VK_3) & 1)
        {
            std::cout << "\n*******************     SCANNING MODULE(S)     *********************\n" << std::endl;

            for (size_t i = 0; i < signatures.size(); i++)
            {
                ModuleScan(signatures[i]);
            }
        }

        if (GetAsyncKeyState(KeyPress::VK_4) & 1)
        {
            std::cout << "\n**************     SCANNING FOR REFLECTIVE DLLs     ****************\n" << std::endl;

            for (size_t i = 0; i < signatures.size(); i++)
            {
                ManualMapScan(signatures[i]);
            }
        }

        if (GetAsyncKeyState(KeyPress::VK_5) & 1)
        {
            std::cout << "\n**************     SCANNING ALL REGIONS     ****************\n" << std::endl;

            for (size_t i = 0; i < signatures.size(); i++)
            {
                ScanAll(signatures[i]);
            }
        }

        if (GetAsyncKeyState(KeyPress::VK_0) & 1)
        {
            break;
        }

        Sleep(10);
    }

    Sleep(10000);
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
        CloseHandle(CreateThread(0, 0, (LPTHREAD_START_ROUTINE) Detection, hModule, 0, 0));
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
