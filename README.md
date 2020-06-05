## Introduction 

`DetectionTool`is a DLL file intended to be injected into a game's process to protect it from foreign intruders.
The tool consists of two core features:

1. *Function hooks* (detects injections)
    - We are hooking `LoadLibraryA` and `RtlGetFullPathName_U`. 
2. *Signature scanners* (detects game hacks once loaded into the game)
    - We scan through the `PEB`'s module list
    - We scan suspect memory regions (`PAGE_EXECUTE_READWRITE`) to detect hacks injected through the `Manual Map` injection technique. 

Console options once injected into a game:

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
5. Fill in info about what modules you wish to scan through. If left blank, it scans through all visible modules. 
6. Run it and choose appropriate console options.

## Detecting Extreme Injector v3.7.2

Injector link: https://www.unknowncheats.me/forum/downloads.php?do=file&id=21570

#### `Remote DLL injection`
<img src="https://github.com/christianshub/DetectionTool/blob/master/Snapshots/1_master_standrd.png" height="200" width="600">

#### `Thread hijack`
<img src="https://github.com/christianshub/DetectionTool/blob/master/Snapshots/2_master_thread.png" height="200" width="600">

#### `LdrLoadDll`
<img src="https://github.com/christianshub/DetectionTool/blob/master/Snapshots/3_master_LdrLoadDll.png" height="200" width="600">

#### `LdrpLoadDll`
<img src="https://github.com/christianshub/DetectionTool/blob/master/Snapshots/4_master_LdrpLoadDll.png" height="200" width="600">

#### `Manual map`
<img src="https://github.com/christianshub/DetectionTool/blob/master/Snapshots/5_master_mm.png" height="200" width="600">

## Detecting Cheat Engine 7.0

Injector link: https://www.cheatengine.org/

#### `Remote DLL injection`
<img src="https://github.com/christianshub/DetectionTool/blob/master/Snapshots/CE.png" height="200" width="600">


## Running the hooks and and signature scans (snapshots)

### Hooks when activated

<img src="https://github.com/christianshub/DetectionTool/blob/master/Snapshots/0_hooks.png" height="200" width="600">

### Signature scanner when running and found a match

<img src="https://github.com/christianshub/DetectionTool/blob/master/Snapshots/0_sigscan.png" height="200" width="600">


### Credits

- Trampoline hook: [jbremer](http://jbremer.org/x86-api-hooking-demystified/#ah-trampoline2), [guidedhacking.com](https://guidedhacking.com/threads/code-detouring-hooking-guide.14185/)
- Signature scanner: [MEMORY_BASIC_INFORMATION](https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-memory_basic_information), [Protection Constants](https://docs.microsoft.com/en-us/windows/win32/memory/memory-protection-constants), [VirtualQuery](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualquery), [bricata.com](https://bricata.com/blog/signature-detection-vs-network-behavior/), [guidedhacking.com](https://guidedhacking.com/threads/external-internal-pattern-scanning-guide.14112/)
