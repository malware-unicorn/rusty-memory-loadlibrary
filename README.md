# rusty-memory-loadlibrary
Load DLLs from memory into another process with rust

- x64bit Only
- Largely based on [fancycode/MemoryModule](https://github.com/fancycode/MemoryModule)
- Will map a DLL in another process' memory
- Uses PEB to build most of the import table, if not will remotely load libraries with a classic dll injection (LoadLibraryA, VirtualAlloc LibName, CreateRemoteThread)
- Uses WriteProcessMemory/ReadProcessMemory to write/read another process
- Uses a shellcode wrapper for TLS & DllMain calls
- Uses CreateRemoteThread (I recommend using EtwpCreateEtwThread instead)
- Threw in a PPID spoof for testing with main

## Prereqs
```
sudo apt-get install gcc-mingw-w64-x86-64
rustup target add x86_64-pc-windows-gnu
```

## Build
```
cargo build --release --target x86_64-pc-windows-gnu
```

## Example Usage:

### Recommended for remote loading
```
let handle = _memory_loadlibary_remote(
    data.as_mut_ptr() as *mut c_void,
    data.len() as u32,
    process_info.p_handle,
);
```

### Recommended for reflective loading
```
let handle = memory_loadlibary_remote(
    data.as_mut_ptr() as *mut c_void, 
    data.len() as u32, 
    NULL
);
```

### Platform Info
- Built with Ubuntu WSL
- Tested on Windows 10
- Tested reflective DLL injection with CobaltStrike, not remote DLL injection

References:
* https://github.com/fancycode/MemoryModule
* https://www.codeproject.com/Tips/139349/Getting-the-address-of-a-function-in-a-DLL-loaded
* https://github.com/hniksic/rust-subprocess/blob/master/src/popen.rs


Future Plans:
- TODO: Freeing memory allocs
- TODO: Get proc address like in `fancycode/MemoryModule`
- TODO: Unhooking NTDLL for writes & reads
- TODO: Probably some code refactoring & better error handling