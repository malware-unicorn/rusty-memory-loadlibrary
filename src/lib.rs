// Lib: rusty-memory-loadlibrary
// Author: malwareunicorn
// Description: Map DLLs from memory into another process
//
// Build: cargo build --release --target x86_64-pc-windows-gnu
// Req: sudo apt-get install gcc-mingw-w64-x86-64
// Req: rustup target add x86_64-pc-windows-gnu

extern crate winapi;

use field_offset::offset_of;
use ntapi::ntapi_base::PCLIENT_ID;
use ntapi::ntldr::LDR_DATA_TABLE_ENTRY;
use ntapi::ntpebteb::PEB;
use ntapi::ntpsapi::{
    NtQueryInformationProcess, ProcessBasicInformation, PEB_LDR_DATA, PPS_ATTRIBUTE_LIST,
    PROCESS_BASIC_INFORMATION,
};
use std::ffi::{CString, OsString};
use std::mem;
use std::os::windows::prelude::OsStringExt;
use winapi::ctypes::c_void;
use winapi::shared::basetsd::{PSIZE_T, SIZE_T};
use winapi::shared::minwindef::{
    BOOL, DWORD, FALSE, FARPROC, HINSTANCE, HMODULE, LPCVOID, LPDWORD, LPVOID, TRUE, ULONG, WORD,
};
use winapi::shared::ntdef::{NTSTATUS, NULL, PHANDLE, POBJECT_ATTRIBUTES};
use winapi::um::consoleapi::AllocConsole;
use winapi::um::libloaderapi::{
    DisableThreadLibraryCalls, FreeLibrary, GetProcAddress, LoadLibraryA,
};
use winapi::um::memoryapi::{ReadProcessMemory, VirtualProtectEx, WriteProcessMemory};
use winapi::um::memoryapi::{VirtualAllocEx, VirtualFreeEx};
use winapi::um::processthreadsapi::{CreateRemoteThread, GetCurrentProcess};
use winapi::um::psapi::{
    EnumProcessModulesEx, GetModuleBaseNameA, GetModuleInformation, LIST_MODULES_ALL, MODULEINFO,
};
use winapi::um::synchapi::{Sleep, WaitForSingleObject};
use winapi::um::sysinfoapi::{GetNativeSystemInfo, SYSTEM_INFO};
use winapi::um::winbase::INFINITE;
use winapi::um::wincon::FreeConsole;
use winapi::um::winnt::{
    ACCESS_MASK, DLL_PROCESS_ATTACH, HANDLE, LPCSTR, LPSTR, MEM_COMMIT, MEM_DECOMMIT, MEM_RESERVE,
    PAGE_READWRITE, PVOID,
};
use winapi::um::winnt::{
    IMAGE_BASE_RELOCATION, IMAGE_DATA_DIRECTORY, IMAGE_DIRECTORY_ENTRY_BASERELOC,
    IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_DIRECTORY_ENTRY_TLS,
    IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY, IMAGE_FILE_DLL, IMAGE_FILE_HEADER,
    IMAGE_FILE_MACHINE_AMD64, IMAGE_IMPORT_DESCRIPTOR, IMAGE_NT_HEADERS, IMAGE_ORDINAL,
    IMAGE_REL_BASED_DIR64, IMAGE_REL_BASED_HIGHLOW, IMAGE_SCN_CNT_INITIALIZED_DATA,
    IMAGE_SCN_CNT_UNINITIALIZED_DATA, IMAGE_SCN_MEM_DISCARDABLE, IMAGE_SCN_MEM_EXECUTE,
    IMAGE_SCN_MEM_NOT_CACHED, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE, IMAGE_SECTION_HEADER,
    IMAGE_SNAP_BY_ORDINAL, IMAGE_TLS_DIRECTORY, MEM_RELEASE, PAGE_EXECUTE, PAGE_EXECUTE_READ,
    PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_NOACCESS, PAGE_NOCACHE, PAGE_READONLY,
    PAGE_WRITECOPY,
};
use winapi::vc::vcruntime::ptrdiff_t;

pub const DOS_SIGNATURE: u16 = 0x5a4d;
pub const PE_SIGNATURE: u32 = 0x00004550;
pub const MAX_DLL_NAME: usize = 33;
pub const _MAX_DLL_FUNC_NAME: usize = 63;

const PROTECTION_FLAGS: [[[u32; 2]; 2]; 2] = [
    [
        // not executable
        [PAGE_NOACCESS, PAGE_WRITECOPY],
        [PAGE_READONLY, PAGE_READWRITE],
    ],
    [
        // executable
        [PAGE_EXECUTE, PAGE_EXECUTE_WRITECOPY],
        [PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE],
    ],
];

// Convert address into function
macro_rules! addr_2_func {
    ($address:expr, $t:ty) => {
        std::mem::transmute::<*const (), $t>($address as _)
    };
}

// Kernel32.dll::LoadLibraryA
type PLoadLibraryA = unsafe extern "system" fn(lp_filename: PVOID) -> u32;
// Kernel32.dll::GetProcAddress
type PCustomGetProcAddress =
    unsafe extern "system" fn(h_module: HMODULE, lp_proc_name: LPCSTR) -> FARPROC;
// Kernel32.dll::FreeLibary
type PFreeLibary = unsafe extern "system" fn(h_module: HMODULE) -> BOOL;
// Kernel32.dll:VirtualAllocEx
type PVirtualAllocEx = unsafe extern "system" fn(
    h_process: HANDLE,
    lp_address: LPVOID,
    dw_size: SIZE_T,
    fl_allocation_type: DWORD,
    fl_protect: DWORD,
) -> LPVOID;
// Kernel32.dll:VirtualFreeEx
type PVirtualFreeEx = unsafe extern "system" fn(
    h_process: HANDLE,
    lp_address: LPVOID,
    dw_size: SIZE_T,
    dw_free_type: DWORD,
) -> BOOL;
type _POpenProcess = unsafe extern "system" fn(
    ProcessHandle: PHANDLE,
    DesiredAccess: ACCESS_MASK,
    ObjectAttributes: POBJECT_ATTRIBUTES,
    ClientId: PCLIENT_ID,
) -> NTSTATUS;
type _PNtWriteVirtualMemory = unsafe extern "system" fn(
    ProcessHandle: HANDLE,
    BaseAddress: PVOID,
    Buffer: PVOID,
    BufferSize: SIZE_T,
    NumberOfBytesWritten: PSIZE_T,
) -> NTSTATUS;
type _PNtCreateThreadEx = unsafe extern "system" fn(
    ThreadHandle: PHANDLE,
    DesiredAccess: ACCESS_MASK,
    ObjectAttributes: POBJECT_ATTRIBUTES,
    ProcessHandle: HANDLE,
    StartRoutine: PVOID,
    Argument: PVOID,
    CreateFlags: ULONG,
    ZeroBits: SIZE_T,
    StackSize: SIZE_T,
    MaximumStackSize: SIZE_T,
    AttributeList: PPS_ATTRIBUTE_LIST,
) -> NTSTATUS;
type ExeEntryProc = unsafe extern "system" fn(c_void) -> u32;
type _DllEntryProc = unsafe extern "system" fn(
    h_inst_dll: HINSTANCE,
    fdw_reason: DWORD,
    lp_reserved: LPVOID,
) -> BOOL;

struct FunctionMap {
    //openprocess: POpenProcess, TODO
    //writemem: PNtWriteVirtualMemory, TODO
    //createthread: PNtCreateThreadEx, TODO
    _load_libary: PLoadLibraryA,
    _get_proc_address: PCustomGetProcAddress,
    _free_libary: PFreeLibary,
    _virtual_alloc: PVirtualAllocEx,
    _virtal_free: PVirtualFreeEx,
}

struct PointerList {
    next: Option<Box<PointerList>>,
    _address: *mut c_void,
}

struct ExportNameEntry {
    _name: LPCSTR,
    _idx: WORD,
}

pub struct MemoryModule {
    header_base: LPVOID,
    code_base: LPVOID,
    h_prochandle: HANDLE,
    h_modules: Vec<HMODULE>,
    initialized: bool,
    is_dll: bool,
    is_relocated: bool,
    functions: FunctionMap,
    _export_table: Vec<ExportNameEntry>,
    entry_point: Option<ExeEntryProc>,
    page_size: DWORD,
    _blocked_memory: Option<PointerList>,
}

struct SectionFinalizedData {
    address: u64,
    aligned_address: u64,
    size: usize,
    characteristics: DWORD,
    last: bool,
}

pub fn _memory_loadlibary(data: PVOID, size: u32) -> u32 {
    return memory_loadlibrary_ex(
        data,
        size,
        _default_loadlibrary,
        _default_getprocaddress,
        _default_freelibrary,
        _default_virtualalloc,
        _default_virtualfree,
        NULL,
    );
}

pub fn _memory_loadlibary_remote(data: PVOID, size: u32, phandle: HANDLE) -> u32 {
    return memory_loadlibrary_ex(
        data,
        size,
        _default_loadlibrary,
        _default_getprocaddress,
        _default_freelibrary,
        _default_virtualalloc,
        _default_virtualfree,
        phandle,
    );
}

fn memory_loadlibrary_ex(
    data: PVOID,
    size: u32,
    load_libary: PLoadLibraryA,
    get_proc_address: PCustomGetProcAddress,
    free_libary: PFreeLibary,
    virtual_alloc: PVirtualAllocEx,
    virtal_free: PVirtualFreeEx,
    phandle: HANDLE,
) -> u32 {
    let mut target_handle: HANDLE = phandle;

    // Check Size
    if check_size(size as u64, mem::size_of::<IMAGE_DOS_HEADER>() as u64) {
        return 0;
    }
    let dos_ptr = data as *mut IMAGE_DOS_HEADER;
    let magic = unsafe { (*dos_ptr).e_magic };
    if DOS_SIGNATURE != magic {
        println!("DOS_SIGNATURE failed!");
        return 0;
    }
    let nt_hdr_offset = unsafe { (*dos_ptr).e_lfanew };
    let nt_ptr = (data as u64 + nt_hdr_offset as u64) as *mut IMAGE_NT_HEADERS;
    if check_size(
        size as u64,
        nt_hdr_offset as u64 + mem::size_of::<IMAGE_NT_HEADERS>() as u64,
    ) {
        println!("check_size failed!");
        return 0;
    }
    let pe_sig = unsafe { (*nt_ptr).Signature };
    if PE_SIGNATURE != pe_sig {
        println!("PE_SIGNATURE failed!");
        return 0;
    }
    let mut file_header = unsafe { (*nt_ptr).FileHeader };
    if file_header.Machine != IMAGE_FILE_MACHINE_AMD64 {
        println!("IMAGE_FILE_MACHINE_AMD64 failed!");
        return 0;
    }
    // Only support section alignments that are a multiple of 2
    let optional_header = unsafe { (*nt_ptr).OptionalHeader };
    let section_align = optional_header.SectionAlignment;
    if section_align & 1 == 1 {
        println!("section_align failed!");
        return 0;
    }
    let last_section_end = get_end_of_sections(nt_ptr, &file_header, section_align);

    let mut sysinfo: SYSTEM_INFO = unsafe { mem::zeroed() };
    unsafe { GetNativeSystemInfo(&mut sysinfo) };
    let aligned_image_size = align_value_up(
        optional_header.SizeOfImage.into(),
        sysinfo.dwPageSize as u64,
    );
    if aligned_image_size != align_value_up(last_section_end as u64, sysinfo.dwPageSize as u64) {
        println!("section end is not matching failed!");
        return 0;
    }

    // reserve memory for image of library
    if target_handle == NULL {
        target_handle = unsafe { GetCurrentProcess() };
    }
    let mut code = unsafe {
        virtual_alloc(
            target_handle,
            //optional_header.ImageBase as PVOID,
            NULL,
            aligned_image_size as usize,
            (MEM_RESERVE | MEM_COMMIT) as u32,
            PAGE_READWRITE,
        )
    };

    if code == NULL {
        // try to allocate memory at arbitrary position
        code = unsafe {
            virtual_alloc(
                target_handle,
                NULL,
                aligned_image_size as usize,
                (MEM_RESERVE | MEM_COMMIT) as u32,
                PAGE_READWRITE,
            )
        };
        if code == NULL {
            return 0;
        }
    }
    // Memory block may not span 4 GB boundaries (64 bit only)
    let mut blocked_memory = PointerList {
        next: None,
        _address: NULL,
    };
    let mut count = 0;
    while code as u64 >> 32 < (code as u64 + aligned_image_size) >> 32 {
        let next = PointerList {
            next: None,
            _address: code,
        };
        blocked_memory.next = Some(Box::new(next));
        code = unsafe {
            virtual_alloc(
                target_handle,
                NULL,
                aligned_image_size as usize,
                (MEM_RESERVE | MEM_COMMIT) as u32,
                PAGE_READWRITE,
            )
        };
        count = count + 1;
        if code == NULL {
            return 0;
        }
    }
    // End 64bit

    let mut memory_module = MemoryModule {
        header_base: NULL,
        code_base: code,
        h_prochandle: target_handle,
        h_modules: Vec::<HMODULE>::new(),
        initialized: false,
        is_dll: !(file_header.Characteristics & IMAGE_FILE_DLL == 0),
        is_relocated: false,
        functions: FunctionMap {
            _load_libary: load_libary,
            _get_proc_address: get_proc_address,
            _free_libary: free_libary,
            _virtual_alloc: virtual_alloc,
            _virtal_free: virtal_free,
        },
        _export_table: Vec::<ExportNameEntry>::new(),
        entry_point: None,
        page_size: sysinfo.dwPageSize,
        _blocked_memory: Some(blocked_memory),
    };

    // commit memory for headers
    if check_size(size as u64, optional_header.SizeOfHeaders as u64) {
        return 0;
    }
    let header_mem = unsafe {
        virtual_alloc(
            target_handle,
            code,
            optional_header.SizeOfHeaders as usize,
            MEM_COMMIT as u32,
            PAGE_READWRITE,
        )
    };

    // update imagebase
    let old_image_base = optional_header.ImageBase;
    unsafe { (*nt_ptr).OptionalHeader.ImageBase = code as u64 };
    let new_image_base = unsafe { (*nt_ptr).OptionalHeader.ImageBase };
    println!("New ImageBase: {:#x}", new_image_base);

    // copy PE header to code
    let mut bytes_written: usize = 0;
    let _status = unsafe {
        _default_memwrite(
            target_handle,
            code,
            data as LPCVOID,
            optional_header.SizeOfHeaders as usize,
            &mut bytes_written,
        )
    };

    // Offset to IMAGE_NT_HEADERS
    memory_module.header_base = (header_mem as u64 + nt_hdr_offset as u64) as LPVOID;

    // copy sections from DLL file block to new memory location
    if !copy_sections(
        data,
        size as usize,
        nt_ptr,
        &mut file_header,
        section_align,
        &mut memory_module,
    ) {
        println!("failed to copy sections!");
        return 0;
    }

    // adjust base address of imported data
    let location_delta: ptrdiff_t = (new_image_base - old_image_base) as ptrdiff_t;
    if location_delta != 0 {
        memory_module.is_relocated =
            perform_base_relocations(nt_ptr, &mut memory_module, location_delta);
    } else {
        memory_module.is_relocated = true;
    }
    // load required dlls and adjust function table of imports
    if !build_import_table(nt_ptr, &mut memory_module) {
        println!("build_import_table failed!");
        return 0;
    }
    // mark memory pages depending on section headers and release
    // sections that are marked as "discardable"
    if !finalize_sections(nt_ptr, &mut file_header, &mut memory_module) {
        println!("finalize_sections failed!");
        return 0;
    }

    let (shellcode_func_wrapper, parameter_ptr) = create_func_wrapper(&mut memory_module);
    // TLS callbacks are executed BEFORE the main loading
    if !execute_tls(
        nt_ptr,
        &mut memory_module,
        shellcode_func_wrapper,
        parameter_ptr,
    ) {
        return 0;
    }

    // get entry point of loaded library
    if optional_header.AddressOfEntryPoint != 0 {
        let dll_entry_ptr =
            memory_module.code_base as u64 + optional_header.AddressOfEntryPoint as u64;
        if memory_module.is_dll {
            unsafe {
                let dll_entry_func = addr_2_func!(shellcode_func_wrapper, PLoadLibraryA);
                let _status = setup_wrapper_params(
                    &mut memory_module,
                    parameter_ptr,
                    dll_entry_ptr,
                    memory_module.code_base as u64,
                    DLL_PROCESS_ATTACH as u64,
                    0,
                );
                let remote_thread = CreateRemoteThread(
                    memory_module.h_prochandle,
                    std::ptr::null_mut(),
                    0,
                    Some(dll_entry_func),
                    parameter_ptr as PVOID,
                    0,
                    std::ptr::null_mut(),
                );
                if remote_thread == 0 as HANDLE {
                    println!("dll_entry_ptr remote_thread failed");
                    return 0;
                }
                WaitForSingleObject(remote_thread, INFINITE);
            }
            memory_module.initialized = true;
        } else {
            // Is EXE
            let entry_func = unsafe { addr_2_func!(dll_entry_ptr, ExeEntryProc) };
            memory_module.entry_point = Some(entry_func);
        }
    } else {
        memory_module.entry_point = None;
    }
    // cleanup
    1
}

unsafe extern "system" fn _default_loadlibrary(lp_filename: PVOID) -> u32 {
    return LoadLibraryA(lp_filename as LPCSTR) as u32;
}

unsafe extern "system" fn _default_getprocaddress(
    h_module: HMODULE,
    lp_proc_name: LPCSTR,
) -> FARPROC {
    return GetProcAddress(h_module, lp_proc_name);
}

unsafe extern "system" fn _default_freelibrary(h_module: HMODULE) -> BOOL {
    return FreeLibrary(h_module);
}

unsafe extern "system" fn _default_virtualalloc(
    h_process: HANDLE,
    lp_address: LPVOID,
    dw_size: SIZE_T,
    fl_allocation_type: DWORD,
    fl_protect: DWORD,
) -> LPVOID {
    return VirtualAllocEx(
        h_process,
        lp_address,
        dw_size,
        fl_allocation_type,
        fl_protect,
    );
}

unsafe extern "system" fn _default_virtualfree(
    h_process: HANDLE,
    lp_address: LPVOID,
    dw_size: SIZE_T,
    dw_free_type: DWORD,
) -> BOOL {
    return VirtualFreeEx(h_process, lp_address, dw_size, dw_free_type);
}

unsafe extern "system" fn _default_memwrite(
    h_process: HANDLE,
    base_address: LPVOID,
    buffer: LPCVOID,
    buffer_size: SIZE_T,
    num_bytes_written: PSIZE_T,
) -> NTSTATUS {
    return WriteProcessMemory(
        h_process,
        base_address,
        buffer,
        buffer_size,
        num_bytes_written,
    );
}

unsafe extern "system" fn _default_memread(
    h_process: HANDLE,
    base_address: LPCVOID,
    buffer: LPVOID,
    buffer_size: SIZE_T,
    num_bytes_written: PSIZE_T,
) -> BOOL {
    return ReadProcessMemory(
        h_process,
        base_address,
        buffer,
        buffer_size,
        num_bytes_written,
    );
}

// Load the library with createremotethread
pub unsafe fn _remotethread_loadlibrary(
    mem_module: *mut MemoryModule,
    lp_filename: &str,
) -> HMODULE {
    let proc_handle = (*mem_module).h_prochandle;
    let virtual_alloc = (*mem_module).functions._virtual_alloc;
    let virtual_free = (*mem_module).functions._virtal_free;
    let get_proc_addr = (*mem_module).functions._get_proc_address;

    // Get address to loadlibrary
    let h_kernel = _sneaky_loadlibrary(mem_module, "kernel32.dll");
    let proc_name = CString::new("LoadLibraryA").unwrap();
    let loadlibrary_addr = get_proc_addr(h_kernel, proc_name.as_ptr());
    let loadlib = addr_2_func!(loadlibrary_addr, PLoadLibraryA);
    // write path to remote process
    let dll_path_buf = lp_filename.as_bytes().to_vec();
    let buf_len = dll_path_buf.len();
    // create buffer
    // virtualalloc
    let memory_address = virtual_alloc(
        proc_handle,
        NULL,
        buf_len + 1,
        MEM_COMMIT as u32,
        PAGE_READWRITE,
    );
    // writeprocessmemory
    let mut bytes_written = 0;
    let _status = _default_memwrite(
        proc_handle,
        memory_address,
        dll_path_buf.as_ptr() as LPCVOID,
        buf_len as usize,
        &mut bytes_written,
    );

    let remote_thread = CreateRemoteThread(
        proc_handle,
        std::ptr::null_mut(),
        0,
        Some(loadlib),
        memory_address as PVOID,
        0,
        std::ptr::null_mut(),
    );
    if remote_thread == 0 as HANDLE {
        println!("loadlibrary remote_thread failed");
        return 0 as HMODULE;
    }
    WaitForSingleObject(remote_thread, INFINITE);
    let mut retry = 0;
    let mut new_module = 0 as HMODULE;
    while new_module == 0 as HMODULE {
        new_module = _sneaky_loadlibrary(mem_module, lp_filename);
        if retry > 3 && new_module == 0 as HMODULE {
            println!("{} failed to load remotely", lp_filename);
            return 0 as HMODULE;
        }
        Sleep(0x1000);
        retry = retry + 1;
    }
    virtual_free(proc_handle, memory_address, 0, MEM_RELEASE);
    new_module
}

// 1) Look up from the PEB
//   a) Alloc PROCESS_BASIC_INFORMATION to heap
//   b) NTQueryInformationProcess,  PROCESS_BASIC_INFORMATION
//   c) pPeb = BasicInfo.PebBaseAddress
//   d) Reading the PEB -> ReadProcessMemory(hProcess, pbi->PebBaseAddress, &peb, sizeof(peb), &dwBytesRead)
//   e) Get the exports
pub unsafe fn _sneaky_loadlibrary(mem_module: *mut MemoryModule, lp_filename: &str) -> HMODULE {
    let proc_handle = (*mem_module).h_prochandle;
    // Remote Proc PEB
    let mut buffer_size = mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32;
    let mut pbi_buffer: Box<[u8]> = vec![0; buffer_size as usize].into_boxed_slice();
    let pbi_ptr = pbi_buffer.as_mut_ptr().cast::<_>() as *mut PROCESS_BASIC_INFORMATION;
    let status = NtQueryInformationProcess(
        proc_handle,
        ProcessBasicInformation,
        pbi_ptr as PVOID,
        buffer_size,
        &mut buffer_size,
    );
    if status != 0 {
        println!("NtQueryInformationProcess status {:#x}", status);
        return 0 as HMODULE;
    }
    let peb_ptr = (*pbi_ptr).PebBaseAddress as u64;
    let mut buf = vec![0; mem::size_of::<PEB>()];
    let mut bytes_read: usize = 0;
    // Read PEB
    _default_memread(
        proc_handle,
        peb_ptr as LPCVOID,
        buf.as_mut_ptr() as LPVOID,
        mem::size_of::<PEB>(),
        &mut bytes_read,
    );
    let mut temp = std::ptr::read(buf.as_mut_ptr() as *const _);
    let ppeb: &mut PEB = &mut temp;
    let peb_ldr_ptr = (*ppeb).Ldr as u64;
    // Read PEB_LDR_DATA
    let mut ldr_buf = vec![0; mem::size_of::<PEB_LDR_DATA>()];
    _default_memread(
        proc_handle,
        peb_ldr_ptr as LPCVOID,
        ldr_buf.as_mut_ptr() as LPVOID,
        mem::size_of::<PEB_LDR_DATA>(),
        &mut bytes_read,
    );
    let mut ldr_temp = std::ptr::read(ldr_buf.as_mut_ptr() as *const PEB_LDR_DATA);
    let ppeb_ldr_data: &mut PEB_LDR_DATA = &mut ldr_temp;
    let mem_order_module_list = (*ppeb_ldr_data).InMemoryOrderModuleList;
    let mut list_entry_ptr = mem_order_module_list.Flink as u64;
    let list_end = mem_order_module_list.Flink as u64;

    let mut ldr_entry_buf = vec![0; mem::size_of::<LDR_DATA_TABLE_ENTRY>()];
    loop {
        _default_memread(
            proc_handle,
            list_entry_ptr as LPCVOID,
            ldr_entry_buf.as_mut_ptr() as LPVOID,
            mem::size_of::<LDR_DATA_TABLE_ENTRY>(),
            &mut bytes_read,
        );
        let mut ldr_entry_temp =
            std::ptr::read(ldr_entry_buf.as_mut_ptr() as *const LDR_DATA_TABLE_ENTRY);
        let p_ldr_data_table_entry: &mut LDR_DATA_TABLE_ENTRY = &mut ldr_entry_temp;

        let full_name_ptr = (*p_ldr_data_table_entry).FullDllName.Buffer as u64;
        let full_name_len = (*p_ldr_data_table_entry).FullDllName.Length as usize;
        let mut full_name_buf = vec![0; full_name_len];
        _default_memread(
            proc_handle,
            full_name_ptr as LPCVOID,
            full_name_buf.as_mut_ptr() as LPVOID,
            full_name_len,
            &mut bytes_read,
        );

        let name_cstring = buff_to_str_w(full_name_buf);
        let name_str = name_cstring.as_c_str().to_str().unwrap();
        if lp_filename.eq_ignore_ascii_case(name_str) {
            let ldr_data_u1 = (*p_ldr_data_table_entry).u1;
            let dll_hmodule = ldr_data_u1.InInitializationOrderLinks.Flink;
            return dll_hmodule as HMODULE;
        }
        // pListEntry = pListEntry->Flink;
        list_entry_ptr = (*p_ldr_data_table_entry).InLoadOrderLinks.Flink as u64;
        if list_entry_ptr == list_end {
            break;
        }
    }
    0 as HMODULE
}

// Helper function for reading a struct remotely
unsafe fn remote_struct_read<T>(proc_handle: HANDLE, ptr_address: u64) -> Option<Vec<u8>> {
    let mut bytes_read: usize = 0;
    let mut buf = vec![0u8; mem::size_of::<T>()];
    match _default_memread(
        proc_handle,
        ptr_address as LPCVOID,
        buf.as_mut_ptr() as LPVOID,
        mem::size_of::<T>(),
        &mut bytes_read,
    ) {
        0 => return None,
        _ => (),
    }
    Some(buf)
}

// Refactored function from ref:
// https://www.codeproject.com/Tips/139349/Getting-the-address-of-a-function-in-a-DLL-loaded
pub unsafe fn _remote_getmodulehandle(mem_module: *mut MemoryModule, lp_filename: &str) -> HMODULE {
    let proc_handle = (*mem_module).h_prochandle;
    let mut h_module: HMODULE = 0 as HMODULE;
    let mut module_array_size: usize = 100;
    let mut h_mods: Vec<HMODULE> = vec![0 as HMODULE; module_array_size];
    let mut num_modules: u32 = 0;
    // get all the handles EnumProcessModulesEx
    let mut _result = EnumProcessModulesEx(
        proc_handle,
        h_mods.as_mut_ptr(),
        (module_array_size * mem::size_of::<HMODULE>()) as DWORD,
        &mut num_modules as LPDWORD,
        LIST_MODULES_ALL,
    );
    num_modules = num_modules / mem::size_of::<HMODULE>() as u32;

    // check if allocated enough
    if num_modules as usize > module_array_size {
        // Call again
        h_mods = Vec::<HMODULE>::with_capacity(num_modules as usize);
        module_array_size = num_modules as usize;
        _result = EnumProcessModulesEx(
            proc_handle,
            h_mods.as_mut_ptr(),
            (module_array_size * mem::size_of::<HMODULE>()) as DWORD,
            &mut num_modules as LPDWORD,
            LIST_MODULES_ALL,
        );
        num_modules = num_modules / mem::size_of::<HMODULE>() as u32;
    }
    // iterate and GetModuleBaseName
    let mut i: usize = 0;
    while i < num_modules as usize {
        let mut name_buf = vec![0; MAX_DLL_NAME];
        let _result_base = GetModuleBaseNameA(
            proc_handle,
            h_mods[i] as HMODULE,
            name_buf.as_mut_ptr() as LPSTR,
            MAX_DLL_NAME as DWORD,
        );
        let name_cstring = buff_to_str(name_buf);
        let name_str = name_cstring.as_c_str().to_str().unwrap();
        if lp_filename.eq_ignore_ascii_case(name_str) {
            h_module = h_mods[i];
            break;
        }
        i = i + 1;
    }
    h_module
}

// For the given export address it will get the forwarded export address
unsafe fn get_forwarded_procaddress(
    mem_module: *mut MemoryModule,
    remote_base_vaddr: u64,
    export_addr: u64,
) -> Result<u64, &'static str> {
    let proc_handle = (*mem_module).h_prochandle;
    let mut forwname_buf = vec![0; _MAX_DLL_FUNC_NAME];
    let mut forwname_bytes_read: usize = 0;
    let forwname_ptr = remote_base_vaddr + export_addr;
    let proc_address: u64;

    match _default_memread(
        proc_handle,
        forwname_ptr as LPCVOID,
        forwname_buf.as_mut_ptr() as LPVOID,
        _MAX_DLL_FUNC_NAME,
        &mut forwname_bytes_read,
    ) {
        0 => return Err("memread failed."),
        _ => (),
    }
    let forwname_cstring = buff_to_str(forwname_buf);
    let forwname_str = forwname_cstring.as_c_str().to_str().unwrap();
    // Split string at dot
    let forwarder_str_parts: Vec<&str> = forwname_str.splitn(2, '.').collect();
    let forwarder_module_name = forwarder_str_parts[0];
    let forwarder_func_name = forwarder_str_parts[1];

    // Get remote module handle
    let remote_module = _remote_getmodulehandle(mem_module, forwarder_module_name);

    // exported by name or ordinal
    if forwarder_func_name.chars().nth(0) == Some('#') {
        // strip #
        let ordinal_name = forwarder_func_name
            .strip_prefix('#')
            .unwrap_or(forwarder_func_name);
        // atoi
        let oridinal_num: u32 = ordinal_name.parse().unwrap_or(0);
        // recursive _remote_getprocaddress
        proc_address = _remote_getprocaddress(mem_module, remote_module, "", oridinal_num, true);
    } else {
        // exported by name
        proc_address =
            _remote_getprocaddress(mem_module, remote_module, forwarder_func_name, 0, false);
    }
    Ok(proc_address)
}

// ref: https://www.codeproject.com/Tips/139349/Getting-the-address-of-a-function-in-a-DLL-loaded
// 64bit only
pub unsafe fn _remote_getprocaddress(
    mem_module: *mut MemoryModule,
    h_module: HMODULE,
    lp_proc_name: &str,
    ordinal: u32,
    use_ordinal: bool,
) -> u64 {
    // check for null handle
    let proc_handle = (*mem_module).h_prochandle;
    let mut remote_module_info: MODULEINFO = mem::zeroed();
    let mod_size = mem::size_of::<MODULEINFO>();
    let remote_base_va: u64;
    let mut export_dir: IMAGE_DATA_DIRECTORY = mem::zeroed();
    let export_table: IMAGE_EXPORT_DIRECTORY;
    let proc_address: u64;
    let mut bytes_read: usize = 0;

    // get the base address with GetModuleInformation
    match GetModuleInformation(
        proc_handle,
        h_module,
        &mut remote_module_info,
        mod_size as u32,
    ) {
        0 => return 0,
        _ => (),
    }
    remote_base_va = remote_module_info.lpBaseOfDll as u64;
    // Read the DOS header and check magic number
    let mut hdr_buf = match remote_struct_read::<IMAGE_DOS_HEADER>(proc_handle, remote_base_va) {
        Some(b) => b,
        _ => return 0,
    };

    // TODO: consider read_unaligned
    let dos_header: IMAGE_DOS_HEADER = std::ptr::read(hdr_buf.as_mut_ptr() as *const _);

    // Read and check the NT signature
    if DOS_SIGNATURE != dos_header.e_magic {
        println!("DOS_SIGNATURE failed!");
        return 0;
    }
    // Read the main header
    let nt_hdr_offset = remote_base_va + dos_header.e_lfanew as u64;
    let mut nt_buf = match remote_struct_read::<IMAGE_NT_HEADERS>(proc_handle, nt_hdr_offset) {
        Some(b) => b,
        _ => return 0,
    };
    let nt_header: IMAGE_NT_HEADERS = std::ptr::read(nt_buf.as_mut_ptr() as *const _);
    if PE_SIGNATURE != nt_header.Signature {
        println!("PE_SIGNATURE failed!");
        return 0;
    }
    // save relative adddress
    if nt_header.OptionalHeader.NumberOfRvaAndSizes >= 1 {
        export_dir.VirtualAddress = nt_header.OptionalHeader.DataDirectory
            [IMAGE_DIRECTORY_ENTRY_EXPORT as usize]
            .VirtualAddress;
        export_dir.Size =
            nt_header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize].Size;
    }
    // Read the main export table
    let exp_va = remote_base_va + export_dir.VirtualAddress as u64;
    let mut exp_buf = match remote_struct_read::<IMAGE_EXPORT_DIRECTORY>(proc_handle, exp_va) {
        Some(b) => b,
        _ => return 0,
    };
    export_table = std::ptr::read(exp_buf.as_mut_ptr() as *const _);
    // Save the absolute address of the table
    let export_func_table_ptr = remote_base_va + export_table.AddressOfFunctions as u64;
    let export_name_table_ptr = remote_base_va + export_table.AddressOfNames as u64;
    let export_ordinal_table_ptr = remote_base_va + export_table.AddressOfNameOrdinals as u64;
    // Allocate memory to copy the tables
    let mut func_table_buf = vec![0u32; export_table.NumberOfFunctions as usize];
    let mut func_name_buf = vec![0u32; export_table.NumberOfNames as usize];
    let mut func_oridinal_buf = vec![0u16; export_table.NumberOfNames as usize];
    _default_memread(
        proc_handle,
        export_func_table_ptr as LPCVOID,
        func_table_buf.as_mut_ptr() as LPVOID,
        export_table.NumberOfFunctions as usize * mem::size_of::<u32>(),
        &mut bytes_read,
    );
    _default_memread(
        proc_handle,
        export_name_table_ptr as LPCVOID,
        func_name_buf.as_mut_ptr() as LPVOID,
        export_table.NumberOfNames as usize * mem::size_of::<u32>(),
        &mut bytes_read,
    );
    _default_memread(
        proc_handle,
        export_ordinal_table_ptr as LPCVOID,
        func_oridinal_buf.as_mut_ptr() as LPVOID,
        export_table.NumberOfNames as usize * mem::size_of::<u16>(),
        &mut bytes_read,
    );

    let exp_addr = match use_ordinal {
        true => {
            // use ordinal
            // make sure ordinal is valid
            if ordinal < export_table.Base
                || (ordinal - export_table.Base) >= export_table.NumberOfFunctions
            {
                return 0;
            }
            let func_table_index = (ordinal - export_table.Base) as usize;

            func_table_buf[func_table_index] as u64
        }
        _ => {
            // Use name
            let mut i = 0;
            let mut func_found: bool = false;
            while i < func_name_buf.len() {
                let mut funcname_buf = vec![0; _MAX_DLL_FUNC_NAME];
                let mut funcname_bytes_read: usize = 0;
                let func_name_ptr = remote_base_va + func_name_buf[i] as u64;
                _default_memread(
                    proc_handle,
                    func_name_ptr as LPCVOID,
                    funcname_buf.as_mut_ptr() as LPVOID,
                    _MAX_DLL_FUNC_NAME,
                    &mut funcname_bytes_read,
                );
                let funcname_cstring = buff_to_str(funcname_buf);
                let funcname_str = funcname_cstring.as_c_str().to_str().unwrap();
                if lp_proc_name.eq(funcname_str) {
                    func_found = true;
                    break;
                }
                i = i + 1;
            }
            if !func_found {
                return 0;
            }

            func_table_buf[func_oridinal_buf[i] as usize] as u64
        }
    };
    // Check if the function is forwarded
    if exp_addr >= export_dir.VirtualAddress as u64
        && exp_addr <= (export_dir.VirtualAddress + export_dir.Size) as u64
    {
        proc_address = match get_forwarded_procaddress(mem_module, remote_base_va, exp_addr) {
            Ok(p) => p,
            Err(_) => 0,
        };
    } else {
        // not forwarded
        proc_address = remote_base_va + exp_addr as u64;
    }
    proc_address
}

// Helper function to check the size
fn check_size(size: u64, expected: u64) -> bool {
    if size < expected {
        println!("check_size failed! {} {}", size, expected);
        return true;
    }
    return false;
}

// Helper function to align virtual allocs
fn align_value_up(value: u64, alignment: u64) -> u64 {
    return (value + alignment - 1) & !(alignment - 1);
}

// Helper function to align virtual allocs
fn align_address_down(value: u64, alignment: u64) -> u64 {
    return value & !(alignment - 1);
}

// This copies the section data to the virtualalloc locations
// TODO: function too big, refactor later
fn copy_sections(
    data: PVOID,
    size: usize,
    nt_ptr: *mut IMAGE_NT_HEADERS,
    file_header: *const IMAGE_FILE_HEADER,
    section_size: u32,
    mem_module: *mut MemoryModule,
) -> bool {
    let proc_handle = unsafe { (*mem_module).h_prochandle };
    let code_base = unsafe { (*mem_module).code_base };
    let virtual_alloc = unsafe { (*mem_module).functions._virtual_alloc };

    let mut image_first_section_ptr = get_first_section_ptr(nt_ptr, file_header);
    let mut section: IMAGE_SECTION_HEADER = unsafe { *image_first_section_ptr };
    let num_sections = unsafe { (*file_header).NumberOfSections };
    let mut _dest: PVOID = 0 as PVOID;

    for _i in 0..num_sections {
        // section doesn't contain data in the dll itself, but may define
        // uninitialized data
        if section.SizeOfRawData == 0 {
            if section_size > 0 {
                let section_offset = code_base as u64 + section.VirtualAddress as u64;
                _dest = unsafe {
                    virtual_alloc(
                        proc_handle,
                        section_offset as PVOID,
                        section_size as usize,
                        MEM_COMMIT as u32,
                        PAGE_READWRITE,
                    )
                };
                if _dest == NULL {
                    return false;
                }
                // Always use position from file to support alignments smaller
                // than page size (allocation above will align to page size).
                _dest = (code_base as u64 + section.VirtualAddress as u64) as PVOID;
                unsafe {
                    let physical_addr = (*image_first_section_ptr).Misc.PhysicalAddress_mut();
                    // NOTE: On 64bit systems we truncate to 32bit here but expand
                    // again later when "PhysicalAddress" is used.
                    (*physical_addr) = (_dest as u64 & 0xffffffff) as DWORD;
                }
                let null_bytes = vec![0; section_size as usize];
                let mut bytes_written = 0;
                let _status = unsafe {
                    _default_memwrite(
                        proc_handle,
                        _dest,
                        null_bytes.as_ptr() as LPCVOID,
                        section_size as usize,
                        &mut bytes_written,
                    )
                };
            }
            // section is empty
        } else {
            if check_size(
                size as u64,
                (section.PointerToRawData + section.SizeOfRawData) as u64,
            ) {
                return false;
            }
            // commit memory block and copy data from dll
            let code_offset = (code_base as u64 + section.VirtualAddress as u64) as PVOID;
            _dest = unsafe {
                virtual_alloc(
                    proc_handle,
                    code_offset,
                    section.SizeOfRawData as usize,
                    MEM_COMMIT as u32,
                    PAGE_READWRITE,
                )
            };
            if _dest == NULL {
                return false;
            }
            _dest = (code_base as u64 + section.VirtualAddress as u64) as PVOID;
            unsafe {
                let physical_addr = (*image_first_section_ptr).Misc.PhysicalAddress_mut();
                // NOTE: On 64bit systems we truncate to 32bit here but expand
                // again later when "PhysicalAddress" is used.
                (*physical_addr) = (_dest as u64 & 0xffffffff) as DWORD;
            }
            // memcopy
            let mut bytes_written = 0;
            let data_offset = data as u64 + section.PointerToRawData as u64;
            let _status = unsafe {
                _default_memwrite(
                    proc_handle,
                    _dest,
                    data_offset as LPCVOID,
                    section.SizeOfRawData as usize,
                    &mut bytes_written,
                )
            };
        }
        image_first_section_ptr = (image_first_section_ptr as u64
            + mem::size_of::<IMAGE_SECTION_HEADER>() as u64)
            as *mut IMAGE_SECTION_HEADER;
        section = unsafe { *image_first_section_ptr };
    }
    true
}

// #define IMAGE_FIRST_SECTION( ntheader ) ((PIMAGE_SECTION_HEADER)  \
// ((ULONG_PTR)(ntheader) +                                      \
//  FIELD_OFFSET( IMAGE_NT_HEADERS, OptionalHeader ) +           \
//  ((ntheader))->FileHeader.SizeOfOptionalHeader   \
// ))
fn get_first_section_ptr(
    nt_ptr: *mut IMAGE_NT_HEADERS,
    file_header: *const IMAGE_FILE_HEADER,
) -> *mut IMAGE_SECTION_HEADER {
    let offset_of_first_hdr = unsafe { (*file_header).SizeOfOptionalHeader };
    let field_offset = offset_of!(IMAGE_NT_HEADERS => OptionalHeader).get_byte_offset();
    let image_first_section_ptr = (nt_ptr as u64 + field_offset as u64 + offset_of_first_hdr as u64)
        as *mut IMAGE_SECTION_HEADER;
    image_first_section_ptr
}

// Loop the sections to get the address end of the sections
fn get_end_of_sections(
    nt_ptr: *mut IMAGE_NT_HEADERS,
    file_header: *const IMAGE_FILE_HEADER,
    section_align: u32,
) -> u64 {
    let mut last_section_end = 0;
    let mut image_first_section_ptr = get_first_section_ptr(nt_ptr, file_header);
    let mut section: IMAGE_SECTION_HEADER = unsafe { *image_first_section_ptr };
    let num_sections = unsafe { (*file_header).NumberOfSections };
    for _i in 0..num_sections {
        let mut _end_of_section = 0;
        if section.SizeOfRawData == 0 {
            _end_of_section = section.VirtualAddress + section_align;
        } else {
            _end_of_section = section.VirtualAddress + section.SizeOfRawData;
        }
        if _end_of_section > last_section_end {
            last_section_end = _end_of_section;
        }
        image_first_section_ptr = (image_first_section_ptr as u64
            + mem::size_of::<IMAGE_SECTION_HEADER>() as u64)
            as *mut IMAGE_SECTION_HEADER;
        section = unsafe { *image_first_section_ptr };
    }
    last_section_end.into()
}

// #define GET_HEADER_DICTIONARY(module, idx)  &(module)->headers->OptionalHeader.DataDirectory[idx]
fn get_header_dictionary(nt_ptr: *mut IMAGE_NT_HEADERS, i: usize) -> *mut IMAGE_DATA_DIRECTORY {
    unsafe {
        let directory: &mut IMAGE_DATA_DIRECTORY = &mut (*nt_ptr).OptionalHeader.DataDirectory[i];
        return directory;
    }
}

// Helper func to calc the pointer's diff and offset
fn offset_pointer(data: PVOID, offset: ptrdiff_t) -> PVOID {
    return (data as ptrdiff_t + offset) as PVOID;
}

// Overwrite the header addreses with the new locations
fn perform_base_relocations(
    nt_ptr: *mut IMAGE_NT_HEADERS,
    mem_module: *mut MemoryModule,
    delta: ptrdiff_t,
) -> bool {
    let code_base = unsafe { (*mem_module).code_base };
    let proc_handle = unsafe { (*mem_module).h_prochandle };
    let mut bytes_read: usize = 0;
    // Use original header here
    let directory = get_header_dictionary(nt_ptr, IMAGE_DIRECTORY_ENTRY_BASERELOC as usize);
    unsafe {
        if (*directory).Size == 0 {
            return delta == 0;
        }
    }
    let mut relocation_ptr = unsafe { code_base as u64 + (*directory).VirtualAddress as u64 };
    let reloc_size = mem::size_of::<IMAGE_BASE_RELOCATION>();
    let mut buf = unsafe {
        match remote_struct_read::<IMAGE_BASE_RELOCATION>(proc_handle, relocation_ptr) {
            Some(b) => b,
            _ => return false,
        }
    };

    unsafe {
        let mut temp = std::ptr::read(buf.as_mut_ptr() as *const _);
        let mut relocation: &mut IMAGE_BASE_RELOCATION = &mut temp;
        while (*relocation).VirtualAddress > 0 {
            let dest = code_base as u64 + (*relocation).VirtualAddress as u64;
            let mut rel_info_ptr =
                offset_pointer(relocation_ptr as PVOID, reloc_size as isize) as u64;
            let size_of_block = (*relocation).SizeOfBlock;
            let block_len = ((size_of_block as usize - reloc_size) / 2) as usize;
            for _i in 0..block_len {
                let mut rel_buf = vec![0; mem::size_of::<u16>()];
                let mut reloc_bytes_read = 0;
                _default_memread(
                    proc_handle,
                    rel_info_ptr as LPCVOID,
                    rel_buf.as_mut_ptr() as LPVOID,
                    mem::size_of::<u16>(),
                    &mut reloc_bytes_read,
                );
                let mut rel_into_bytes = std::ptr::read(rel_buf.as_mut_ptr() as *const _);
                let rel_info: &mut u16 = &mut rel_into_bytes;
                let rel_type = (*rel_info >> 12) as u16;
                let rel_offset = *rel_info & 0xfff;
                let patch_addr_hl = dest + rel_offset as u64;

                let mut addr_hl_buf = vec![0; mem::size_of::<u16>()];
                let mut addr_hl_bytes_read = 0;
                _default_memread(
                    proc_handle,
                    patch_addr_hl as LPCVOID,
                    addr_hl_buf.as_mut_ptr() as LPVOID,
                    mem::size_of::<u64>(),
                    &mut addr_hl_bytes_read,
                );
                let mut addr_hl_bytes = std::ptr::read(addr_hl_buf.as_mut_ptr() as *const _);
                let addr_hl_info: &mut u64 = &mut addr_hl_bytes;
                match rel_type {
                    IMAGE_REL_BASED_HIGHLOW => {
                        // patch location
                        let mut bytes_written = 0;
                        let new_patch = (*addr_hl_info) as isize + delta;
                        let delta_buf = ((new_patch as u32).to_le_bytes()).to_vec();
                        _default_memwrite(
                            proc_handle,
                            patch_addr_hl as LPVOID,
                            delta_buf.as_ptr() as LPCVOID,
                            mem::size_of::<u32>(),
                            &mut bytes_written,
                        );
                        // TODO: check status
                    }
                    IMAGE_REL_BASED_DIR64 => {
                        let mut bytes_written = 0;
                        let new_patch = (*addr_hl_info) as isize + delta;
                        let delta_buf = ((new_patch as u64).to_le_bytes()).to_vec();
                        _default_memwrite(
                            proc_handle,
                            patch_addr_hl as LPVOID,
                            delta_buf.as_ptr() as LPCVOID,
                            mem::size_of::<u64>(),
                            &mut bytes_written,
                        );
                        // TODO: check status
                    }
                    _ => {}
                };

                rel_info_ptr = rel_info_ptr + mem::size_of::<u16>() as u64;
            }
            relocation_ptr = offset_pointer(relocation_ptr as PVOID, size_of_block as isize) as u64;
            _default_memread(
                proc_handle,
                relocation_ptr as LPCVOID,
                buf.as_mut_ptr() as LPVOID,
                reloc_size,
                &mut bytes_read,
            );
            temp = std::ptr::read(buf.as_mut_ptr() as *const _);
            relocation = &mut temp;
        }
    }
    true
}

// Helper function to covert buffer to wide str
fn buff_to_str_w(buf: Vec<u16>) -> CString {
    let slice = buf.as_slice();
    let full_name_ostr: OsString = OsStringExt::from_wide(slice);
    let full_name_str: &str = full_name_ostr.to_str().unwrap();
    let name_cstring = unsafe { buff_to_str(full_name_str.as_bytes().to_vec()) };
    return name_cstring;
}

// Helper function to convert buff to str
unsafe fn buff_to_str(buf: Vec<u8>) -> CString {
    let name_cstr = CString::from_vec_unchecked(buf);
    let name_raw = name_cstr.into_raw();
    return CString::from_raw(name_raw);
}

// 1) Check if self proc handle
// 2) Look up from the PEB
//   a) Alloc PROCESS_BASIC_INFORMATION to heap
//   b) NTQueryInformationProcess,  PROCESS_BASIC_INFORMATION
//   c) pPeb = BasicInfo.PebBaseAddress
//   d) Reading the PEB -> ReadProcessMemory(hProcess, pbi->PebBaseAddress, &peb, sizeof(peb), &dwBytesRead)
//   e) Get the exports
// 3) If doesn't exists, call loadlibrary (worst case)
// TODO: function too big. refactor later
fn build_import_table(nt_ptr: *mut IMAGE_NT_HEADERS, mem_module: *mut MemoryModule) -> bool {
    let code_base = unsafe { (*mem_module).code_base as u64 };
    let proc_handle = unsafe { (*mem_module).h_prochandle };
    let get_proc_addr = unsafe { (*mem_module).functions._get_proc_address };
    let mut _status: NTSTATUS = 1;
    let directory = get_header_dictionary(nt_ptr, IMAGE_DIRECTORY_ENTRY_IMPORT as usize);
    unsafe {
        if (*directory).Size == 0 {
            return false;
        }
    }
    let mut import_desc_ptr = unsafe { code_base as u64 + (*directory).VirtualAddress as u64 };
    let import_dir_size = unsafe { (*directory).Size };
    let import_desc_size = mem::size_of::<IMAGE_IMPORT_DESCRIPTOR>();
    let mut buf = vec![0; import_desc_size as usize];
    let mut bytes_read: usize = 0;
    let _result = unsafe {
        _default_memread(
            proc_handle,
            import_desc_ptr as LPCVOID,
            buf.as_mut_ptr() as LPVOID,
            import_desc_size,
            &mut bytes_read,
        )
    };
    if bytes_read != import_desc_size {
        println!("failed to read directory!");
        return false;
    }
    unsafe {
        let mut temp = std::ptr::read(buf.as_mut_ptr() as *const _);
        let mut import_desc: &mut IMAGE_IMPORT_DESCRIPTOR = &mut temp;
        let import_dir_len =
            code_base as u64 + (*directory).VirtualAddress as u64 + import_dir_size as u64;
        while import_desc_ptr < import_dir_len && (*import_desc).Name != 0 {
            let name_ptr = code_base as u64 + (*import_desc).Name as u64;
            let mut name_buf = vec![0; MAX_DLL_NAME];
            let mut name_bytes_read: usize = 0;
            _default_memread(
                proc_handle,
                name_ptr as LPCVOID,
                name_buf.as_mut_ptr() as LPVOID,
                MAX_DLL_NAME,
                &mut name_bytes_read,
            );

            let name_cstring = buff_to_str(name_buf);
            let name_str = name_cstring.as_c_str().to_str().unwrap();
            // LoadLibrary
            let mut dll_module = _sneaky_loadlibrary(mem_module, name_str);
            if dll_module == 0 as HMODULE {
                dll_module = _remotethread_loadlibrary(mem_module, name_str);
                if dll_module == 0 as HMODULE {
                    return false;
                }
            }
            // Add to list of modules
            (*mem_module).h_modules.push(dll_module);
            let mut _thunk_ref: u64 = 0;
            let mut _func_ref: u64 = 0;
            let original_first_thunk: u64 = *((*import_desc).u.OriginalFirstThunk()) as u64;
            let first_thunk = (*import_desc).FirstThunk as u64;
            if original_first_thunk != 0 {
                _thunk_ref = code_base + original_first_thunk;
                _func_ref = code_base + first_thunk;
            } else {
                // no hint table
                _thunk_ref = code_base + first_thunk;
                _func_ref = code_base + first_thunk;
            }
            // Loop through thunks
            loop {
                // read thunk_ref
                let mut thunk_buf = vec![0; mem::size_of::<u64>()];
                let mut thunk_bytes_read = 0;
                _default_memread(
                    proc_handle,
                    _thunk_ref as LPCVOID,
                    thunk_buf.as_mut_ptr() as LPVOID,
                    mem::size_of::<u64>(),
                    &mut thunk_bytes_read,
                );
                let mut thunk_into_bytes = std::ptr::read(thunk_buf.as_mut_ptr() as *const u64);
                let thunk_addr: &mut u64 = &mut thunk_into_bytes;
                let snapped_thunk = IMAGE_SNAP_BY_ORDINAL(*thunk_addr) as u64;
                let mut _func_ref_value_ptr = 0;
                if *thunk_addr != 0 && snapped_thunk != 0 {
                    let ordinal_name_ptr = IMAGE_ORDINAL(*thunk_addr);
                    let proc_addr = get_proc_addr(dll_module, ordinal_name_ptr as LPCSTR);
                    // write thunk_ref
                    let mut bytes_written = 0;
                    let func_ref_value = ((proc_addr as u64).to_le_bytes()).to_vec();
                    _status = _default_memwrite(
                        proc_handle,
                        _func_ref as LPVOID,
                        func_ref_value.as_ptr() as LPCVOID,
                        mem::size_of::<u64>(),
                        &mut bytes_written,
                    );
                    _func_ref_value_ptr = proc_addr as u64;
                } else if *thunk_addr != 0 {
                    //IMAGE_IMPORT_BY_NAME hack
                    let image_import_ptr = code_base + (*thunk_addr) as u64;
                    let proc_name_ptr = image_import_ptr + mem::size_of::<WORD>() as u64;

                    let mut funcname_buf = vec![0; _MAX_DLL_FUNC_NAME];
                    let mut funcname_bytes_read: usize = 0;
                    _default_memread(
                        proc_handle,
                        proc_name_ptr as LPCVOID,
                        funcname_buf.as_mut_ptr() as LPVOID,
                        _MAX_DLL_FUNC_NAME,
                        &mut funcname_bytes_read,
                    );
                    let funcname_cstring = buff_to_str(funcname_buf);
                    let funcname_str = funcname_cstring.as_c_str().to_str().unwrap();
                    // Hack to get address from PEB dlls, if not parse exports remotely
                    let mut proc_addr =
                        get_proc_addr(dll_module, funcname_cstring.as_ptr() as LPCSTR) as u64;
                    if proc_addr as u64 == 0 {
                        proc_addr =
                            _remote_getprocaddress(mem_module, dll_module, funcname_str, 0, false);
                    }
                    // write thunk_ref
                    let mut bytes_written = 0;
                    let func_ref_value = (proc_addr.to_le_bytes()).to_vec();
                    _status = _default_memwrite(
                        proc_handle,
                        _func_ref as LPVOID,
                        func_ref_value.as_ptr() as LPCVOID,
                        mem::size_of::<u64>(),
                        &mut bytes_written,
                    );
                    _func_ref_value_ptr = proc_addr;
                }
                if _func_ref_value_ptr == 0 {
                    break;
                }
                // increment thunk
                _thunk_ref = _thunk_ref + mem::size_of::<u64>() as u64;
                _func_ref = _func_ref + mem::size_of::<u64>() as u64;
            }
            import_desc_ptr = import_desc_ptr + import_desc_size as u64;
            _default_memread(
                proc_handle,
                import_desc_ptr as LPCVOID,
                buf.as_mut_ptr() as LPVOID,
                import_desc_size,
                &mut bytes_read,
            );
            temp = std::ptr::read(buf.as_mut_ptr() as *const _);
            import_desc = &mut temp;
        }
    }
    true
}

// Helper function to retrieve the section size
fn get_real_section_size(nt_ptr: *mut IMAGE_NT_HEADERS, section: &IMAGE_SECTION_HEADER) -> usize {
    let optional_header = unsafe { (*nt_ptr).OptionalHeader };
    let mut size: usize = (*section).SizeOfRawData as usize;
    if size == 0 {
        if ((*section).Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) != 0 {
            size = optional_header.SizeOfInitializedData as usize;
        } else if ((*section).Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) != 0 {
            size = optional_header.SizeOfUninitializedData as usize;
        }
    }
    size
}

// Change the protection of the section
fn finalize_section(
    nt_ptr: *mut IMAGE_NT_HEADERS,
    mem_module: *mut MemoryModule,
    section_data: &SectionFinalizedData,
) -> bool {
    let proc_handle = unsafe { (*mem_module).h_prochandle };
    let virtual_free = unsafe { (*mem_module).functions._virtal_free };
    if (*section_data).size == 0 {
        return true;
    }
    let optional_header = unsafe { (*nt_ptr).OptionalHeader };
    let page_size = unsafe { (*mem_module).page_size as usize };
    if ((*section_data).characteristics & IMAGE_SCN_MEM_DISCARDABLE) != 0 {
        if (*section_data).address == (*section_data).aligned_address && (*section_data).last
            || optional_header.SectionAlignment as usize == page_size
            || (*section_data).size % page_size == 0
        {
            // Only allowed to decommit whole pages
            unsafe {
                virtual_free(
                    proc_handle,
                    (*section_data).address as LPVOID,
                    (*section_data).size,
                    MEM_DECOMMIT,
                )
            };
        }
        return true;
    }
    // determine protection flags based on characteristics
    let executable = (((*section_data).characteristics & IMAGE_SCN_MEM_EXECUTE) != 0) as usize;
    let readable = (((*section_data).characteristics & IMAGE_SCN_MEM_READ) != 0) as usize;
    let writeable = (((*section_data).characteristics & IMAGE_SCN_MEM_WRITE) != 0) as usize;
    let mut protect = PROTECTION_FLAGS[executable][readable][writeable];
    if ((*section_data).characteristics & IMAGE_SCN_MEM_NOT_CACHED) != 0 {
        protect = protect | PAGE_NOCACHE;
    }
    let mut old_protect: u32 = protect;
    // change memory access flags
    unsafe {
        match VirtualProtectEx(
            proc_handle,
            (*section_data).address as LPVOID,
            (*section_data).size,
            protect,
            &mut old_protect,
        ) {
            FALSE => return false,
            _ => (),
        };
    }
    true
}

// Loop through all sections and change access flags
fn finalize_sections(
    nt_ptr: *mut IMAGE_NT_HEADERS,
    file_header: *const IMAGE_FILE_HEADER,
    mem_module: *mut MemoryModule,
) -> bool {
    // loop through all sections and change access flags
    let page_size = unsafe { (*mem_module).page_size };
    let optional_header = unsafe { (*nt_ptr).OptionalHeader };
    let mut image_first_section_ptr = get_first_section_ptr(nt_ptr, file_header);
    let mut section: IMAGE_SECTION_HEADER;
    let num_sections = unsafe { (*file_header).NumberOfSections };
    let mut _dest: PVOID = 0 as PVOID;
    section = unsafe { *image_first_section_ptr };

    // "PhysicalAddress" might have been truncated to 32bit above, expand to
    // 64bits again.
    let image_offset = optional_header.ImageBase as u64 & 0xffffffff00000000;
    let physical_addr = unsafe { section.Misc.PhysicalAddress_mut() };
    let section_addr = ((*physical_addr) as u64 | image_offset) as u64;
    let mut section_data = SectionFinalizedData {
        address: section_addr,
        aligned_address: align_address_down(section_addr, page_size as u64),
        size: get_real_section_size(nt_ptr, &section),
        characteristics: section.Characteristics,
        last: false,
    };
    // section++
    image_first_section_ptr = (image_first_section_ptr as u64
        + mem::size_of::<IMAGE_SECTION_HEADER>() as u64)
        as *mut IMAGE_SECTION_HEADER;
    section = unsafe { *image_first_section_ptr };
    for _i in 1..num_sections {
        let physical_address = unsafe { section.Misc.PhysicalAddress_mut() };
        let section_address = ((*physical_address) as u64 | image_offset) as u64;
        let aligned_address = align_address_down(section_address, page_size as u64);
        let section_size = get_real_section_size(nt_ptr, &section);
        if section_data.aligned_address == aligned_address
            || section_data.address + section_data.size as u64 > aligned_address
        {
            if (section.Characteristics & IMAGE_SCN_MEM_DISCARDABLE) == 0
                || (section_data.characteristics & IMAGE_SCN_MEM_DISCARDABLE) == 0
            {
                section_data.characteristics = (section_data.characteristics
                    | section.Characteristics)
                    & !IMAGE_SCN_MEM_DISCARDABLE;
            } else {
                section_data.characteristics =
                    section_data.characteristics | section.Characteristics;
            }
            section_data.size =
                section_address as usize + section_size - section_data.address as usize;
        } else {
            if !finalize_section(nt_ptr, mem_module, &section_data) {
                return false;
            }
            section_data.address = section_address;
            section_data.aligned_address = aligned_address;
            section_data.size = section_size;
            section_data.characteristics = section.Characteristics;
        }
        image_first_section_ptr = (image_first_section_ptr as u64
            + mem::size_of::<IMAGE_SECTION_HEADER>() as u64)
            as *mut IMAGE_SECTION_HEADER;
        section = unsafe { *image_first_section_ptr };
    }
    section_data.last = true;
    if !finalize_section(nt_ptr, mem_module, &section_data) {
        return false;
    }
    true
}

// This function puts a function wrapper in the target process. This is a hack
// that was needed for executing remote functions such as TLS.
// func(arg1, arg2, arg3)
/* Function wrapper using fastcall
    push    rbp
    mov     rbp, rsp
    mov     rbx, rcx
    mov     rax, [rbx+0x18]
    mov     r8, [rax]
    mov     rax, [rbx+0x10]
    mov     rdx, [rax]
    mov     rax, [rbx+0x8]
    mov     rcx, [rax]
    mov     rax, [rbx]
    mov     rax, [rax]
    call    rax
    xor     rax, rax
    pop     rbp
    ret
*/
fn create_func_wrapper(mem_module: *mut MemoryModule) -> (u64, u64) {
    let proc_handle = unsafe { (*mem_module).h_prochandle };
    let virtual_alloc = unsafe { (*mem_module).functions._virtual_alloc };
    let mut bytes_written: usize = 0;

    let tls_wrapper: Vec<u8> = vec![
        0x55, 0x48, 0x89, 0xE5, 0x48, 0x89, 0xCB, 0x48, 0x8B, 0x43, 0x18, 0x4C, 0x8B, 0x00, 0x48,
        0x8B, 0x43, 0x10, 0x48, 0x8B, 0x10, 0x48, 0x8B, 0x43, 0x08, 0x48, 0x8B, 0x08, 0x48, 0x8B,
        0x03, 0x48, 0x8B, 0x00, 0xFF, 0xD0, 0x48, 0x31, 0xC0, 0x5D, 0xC3,
    ];

    let tls_wrapper_func = unsafe {
        virtual_alloc(
            proc_handle,
            NULL,
            tls_wrapper.len(),
            MEM_COMMIT as u32,
            PAGE_EXECUTE_READWRITE,
        )
    };

    let mut _status = unsafe {
        _default_memwrite(
            proc_handle,
            tls_wrapper_func,
            tls_wrapper.as_ptr() as LPCVOID,
            tls_wrapper.len(),
            &mut bytes_written,
        )
    };
    // Create tls callback parameters
    let parameter_ptr =
        unsafe { virtual_alloc(proc_handle, NULL, 76, MEM_COMMIT as u32, PAGE_READWRITE) };

    (tls_wrapper_func as u64, parameter_ptr as u64)
}

// This function sets up the parameter array for the wrapper function.
// This is a hack that was needed for executing remote functions such as TLS.
fn setup_wrapper_params(
    mem_module: *mut MemoryModule,
    parameter_ptr: u64,
    arg0_func: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
) -> i32 {
    let proc_handle = unsafe { (*mem_module).h_prochandle };
    let mut bytes_written: usize = 0;

    let mut arg0_ptr =
        ((parameter_ptr as u64 + (mem::size_of::<u64>() as u64 * 5)).to_le_bytes()).to_vec();
    let mut arg1_ptr =
        ((parameter_ptr as u64 + (mem::size_of::<u64>() as u64 * 6)).to_le_bytes()).to_vec();
    let mut arg2_ptr =
        ((parameter_ptr as u64 + (mem::size_of::<u64>() as u64 * 7)).to_le_bytes()).to_vec();
    let mut arg3_ptr =
        ((parameter_ptr as u64 + (mem::size_of::<u64>() as u64 * 8)).to_le_bytes()).to_vec();
    let mut end_ptr = ((0 as u64).to_le_bytes()).to_vec();

    let mut arg1_buff = (arg1.to_le_bytes()).to_vec();
    let mut arg2_buff = ((arg2 as u32).to_le_bytes()).to_vec();
    let mut arg3_buff = ((arg3 as u64).to_le_bytes()).to_vec();

    arg0_ptr.append(&mut arg1_ptr);
    arg0_ptr.append(&mut arg2_ptr);
    arg0_ptr.append(&mut arg3_ptr);
    arg0_ptr.append(&mut end_ptr);

    arg1_buff.append(&mut arg2_buff);
    arg1_buff.append(&mut arg3_buff);
    let mut arg0_buff = (arg0_func.to_le_bytes()).to_vec();
    arg0_buff.append(&mut arg1_buff);
    arg0_ptr.append(&mut arg0_buff);
    let _status = unsafe {
        _default_memwrite(
            proc_handle,
            parameter_ptr as PVOID,
            arg0_ptr.as_ptr() as LPCVOID,
            arg0_ptr.len(),
            &mut bytes_written,
        )
    };
    _status
}

// Execute all TLS functions
fn execute_tls(
    nt_ptr: *mut IMAGE_NT_HEADERS,
    mem_module: *mut MemoryModule,
    tls_wrapper_func: u64,
    parameter_ptr: u64,
) -> bool {
    let code_base = unsafe { (*mem_module).code_base };
    let proc_handle = unsafe { (*mem_module).h_prochandle };
    let mut bytes_read: usize = 0;
    let directory = get_header_dictionary(nt_ptr, IMAGE_DIRECTORY_ENTRY_TLS as usize);
    unsafe {
        if (*directory).Size == 0 {
            return true;
        }
    }
    let tls_dir_ptr = unsafe { code_base as u64 + (*directory).VirtualAddress as u64 };
    let tls_dir_size = mem::size_of::<IMAGE_TLS_DIRECTORY>();
    let mut dir_buf = vec![0; tls_dir_size as usize];
    let _result = unsafe {
        _default_memread(
            proc_handle,
            tls_dir_ptr as LPCVOID,
            dir_buf.as_mut_ptr() as LPVOID,
            tls_dir_size,
            &mut bytes_read,
        )
    };
    if bytes_read != tls_dir_size {
        println!("failed to read directory!");
        return false;
    }
    unsafe {
        let load_tls = addr_2_func!(tls_wrapper_func, PLoadLibraryA);
        let mut dir_temp = std::ptr::read(dir_buf.as_mut_ptr() as *const _);
        let tls_directory: &mut IMAGE_TLS_DIRECTORY = &mut dir_temp;
        let mut tls_callback_ptr = (*tls_directory).AddressOfCallBacks;
        if tls_callback_ptr != 0 {
            let buf_size = mem::size_of::<u64>();
            let mut buf = vec![0; buf_size as usize];
            loop {
                let _result = _default_memread(
                    proc_handle,
                    tls_callback_ptr as LPCVOID,
                    buf.as_mut_ptr() as LPVOID,
                    buf_size,
                    &mut bytes_read,
                );
                let mut temp = std::ptr::read(buf.as_mut_ptr() as *const u64);
                let tls_callback_func_ptr = &mut temp;
                if (*tls_callback_func_ptr) as u64 == 0 {
                    break;
                }
                let _status = setup_wrapper_params(
                    mem_module,
                    parameter_ptr,
                    (*tls_callback_func_ptr) as u64,
                    code_base as u64,
                    DLL_PROCESS_ATTACH as u64,
                    0,
                );
                let remote_thread = CreateRemoteThread(
                    proc_handle,
                    std::ptr::null_mut(),
                    0,
                    Some(load_tls),
                    parameter_ptr as PVOID,
                    0,
                    std::ptr::null_mut(),
                );
                if remote_thread == 0 as HANDLE {
                    println!("TLS remote_thread failed");
                    return false;
                }
                WaitForSingleObject(remote_thread, INFINITE);
                tls_callback_ptr = tls_callback_ptr + mem::size_of::<u64>() as u64;
            }
        }
    }
    true
}



// TODO
fn _memory_get_proc_address() -> u64 {
    0
}

// TODO
fn _memory_free_library() -> u32 {
    0
}

// Left this in here for dll testing.
#[warn(non_snake_case)]
#[no_mangle]
extern "stdcall" fn DllMain(
    h_module: HINSTANCE,
    dw_reason: DWORD,
    _: *const ::std::ffi::c_void,
) -> BOOL {
    if dw_reason == DLL_PROCESS_ATTACH {
        unsafe {
            DisableThreadLibraryCalls(h_module);
        }
        ::std::thread::spawn(|| {
            if cfg!(debug_assertions) {
                unsafe {
                    AllocConsole();
                }
            }
            // PUT FUNCTION HERE $function();
            if cfg!(debug_assertions) {
                unsafe {
                    FreeConsole();
                }
            }
        });
    }
    TRUE
}


// TODO: unhook later
// TODO: [FUTURE] Unhook NTDLL APIs using the PEB
fn _unhook_ntdll() -> u32 {
    0
}