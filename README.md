## Introduction 

`DetectionTool`is a DLL file intended to be injected into a process to protect it from foreign intruders.
The tool consists of two core features:

1. *Function hooks* (detects injections)
    - hooks `LoadLibraryA` and `RtlGetFullPathName_U`. 
2. *Signature scanners* (detects malicious sigs)
    - scan through the `PEB`'s module list
    - scan suspect memory regions (`PAGE_EXECUTE_READWRITE`) to detect hacks injected through the `Manual Map` injection technique. 

Console options once injected into a target process:

<img src="https://github.com/christianshub/DetectionTool/blob/master/Snapshots/0_consoleOptions.png" height="200" width="600">

## Operation system, project, etc.

- IDE: Visual Studio 2019 (x86 project).
- OS: Windows 10, version 1909.
- Unit test framework: https://github.com/google/googletest

## Setup

1. Compile the source code
2. Run it one time - a folder and a `config.ini` file should be created on your desktop.
3. Navigate to `Desktop/Detection/config.ini`.
4. Fill in info about which signatures to scan for (e.g.: `4D5A90`, `4d5a90`, `4d??90`)
5. Fill in info about which modules you wish to scan through. If left blank, it scans through all visible modules. 
6. Run it and choose appropriate console options.

## Detecting Extreme Injector v3.7.2

Injector link: https://www.unknowncheats.me/forum/downloads.php?do=file&id=21570

#### `Remote DLL injection`
<img src="https://github.com/christianshub/DetectionTool/blob/master/Snapshots/Extreme/1_master_standrd.png" height="200" width="600">

#### `Thread hijack`
<img src="https://github.com/christianshub/DetectionTool/blob/master/Snapshots/Extreme/2_master_thread.png" height="200" width="600">

#### `LdrLoadDll`
<img src="https://github.com/christianshub/DetectionTool/blob/master/Snapshots/Extreme/3_master_LdrLoadDll.png" height="200" width="600">

#### `LdrpLoadDll`
<img src="https://github.com/christianshub/DetectionTool/blob/master/Snapshots/Extreme/4_master_LdrpLoadDll.png" height="200" width="600">

#### `Manual map`
<img src="https://github.com/christianshub/DetectionTool/blob/master/Snapshots/Extreme/5_master_mm.png" height="200" width="600">

## Detecting Cheat Engine 7.0

Injector link: https://www.cheatengine.org/

#### `Remote DLL injection` - (detected: hook + sigscan)
<img src="https://github.com/christianshub/DetectionTool/blob/master/Snapshots/CheatEngine/CE.png" height="200" width="400">


## Detecting Winject 1.7b

Injector link: https://www.unknowncheats.me/forum/downloads.php?do=file&id=578

#### `Remote DLL injection`
<img src="https://github.com/christianshub/DetectionTool/blob/master/Snapshots/Winject/Winject.png" height="200" width="600">

## Detecting Xenos 2.3.2.7

Injector link: https://www.unknowncheats.me/forum/downloads.php?do=file&id=23686

#### `Remote DLL injection`
<img src="https://github.com/christianshub/DetectionTool/blob/master/Snapshots/Xenos/1_xenos_native.png" height="200" width="600">

#### `Manual map`
<img src="https://github.com/christianshub/DetectionTool/blob/master/Snapshots/Xenos/2_xenos_mm.png" height="200" width="600">

#### `Kernel Create thread`
<img src="https://github.com/christianshub/DetectionTool/blob/master/Snapshots/Xenos/3_xenos_KernelCreateThread.png" height="200" width="600">

#### `Kernel APC`
<img src="https://github.com/christianshub/DetectionTool/blob/master/Snapshots/Xenos/4_xenos_KernelAPC.png" height="200" width="600">


#### `Kernal Manual Map`
<img src="https://github.com/christianshub/DetectionTool/blob/master/Snapshots/Xenos/5_xenos_KernelManualMap.png" height="200" width="600">

## Closing thoughts

1. *Function hooks*
    - `RtlGetFullPathName_U` proved effective when monitoring injections. `LoadLibraryA`, not so much.
2. *Signature scanners*
    - Many injectors avoid revealing information about their payload in the `PEB`, hence scanning the `PEB` seems meaningless. Scanning in suspect memory regions proved more useful. We could catch Extreme injector's hidden payload this way. This was not the case against Xenos injector, however.  

## References

- Trampoline hook: [jbremer](http://jbremer.org/x86-api-hooking-demystified/#ah-trampoline2), [guidedhacking.com](https://guidedhacking.com/threads/code-detouring-hooking-guide.14185/), [RtlGetFullPathName_U](https://googleprojectzero.blogspot.com/2016/02/), [doxygen.reactos.org](https://doxygen.reactos.org/df/d1a/RtlGetFullPathName__U_8c_source.html)
- Signature scanner: [MEMORY_BASIC_INFORMATION](https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-memory_basic_information), [Protection Constants](https://docs.microsoft.com/en-us/windows/win32/memory/memory-protection-constants), [VirtualQuery](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualquery), [bricata.com](https://bricata.com/blog/signature-detection-vs-network-behavior/), [guidedhacking.com](https://guidedhacking.com/threads/external-internal-pattern-scanning-guide.14112/)
