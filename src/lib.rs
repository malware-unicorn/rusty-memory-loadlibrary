// cargo build --release --target x86_64-pc-windows-gnu --lib 
// sudo apt-get install gcc-mingw-w64-x86-64
// This is a lightweight port of https://github.com/fancycode/MemoryModule
// TODO: Modules should strive to be below 500 lines


// 1) Unhook NTDLL APIs using the PEB
// 2) Link the ntdll functions to the memory loader
extern crate winapi;

use std::mem;
use winapi::um::libloaderapi::{
    DisableThreadLibraryCalls,
    LoadLibraryA,
    GetProcAddress,
    FreeLibrary,
};
use winapi::um::consoleapi::AllocConsole;
use winapi::um::wincon::FreeConsole;
use winapi::shared::minwindef::{
    BOOL,
    TRUE,
    DWORD,
    HINSTANCE, 
    FARPROC,
    HMODULE,
    LPVOID,
    LPCVOID,
    ULONG,
    WORD,
};
use winapi::um::winnt::{
    LPCSTR,
    DLL_PROCESS_ATTACH,
    PVOID,
    HANDLE,
    ACCESS_MASK,
    MEM_RESERVE,
    MEM_COMMIT,
    PAGE_READWRITE,
};
use winapi::shared::basetsd::{SIZE_T,PSIZE_T};
use winapi::shared::ntdef::{
    POBJECT_ATTRIBUTES,
    NTSTATUS,
    PHANDLE,
    NULL,
    LIST_ENTRY, 
    WCHAR,
};
use ntapi::ntapi_base::PCLIENT_ID;
use ntapi::ntpsapi::PPS_ATTRIBUTE_LIST;
use winapi::um::memoryapi::{
    VirtualAllocEx,
    VirtualFreeEx
};
use winapi::um::winnt::{
    IMAGE_DOS_HEADER, 
    IMAGE_NT_HEADERS, 
    IMAGE_OPTIONAL_HEADER, 
    IMAGE_DATA_DIRECTORY, 
    IMAGE_EXPORT_DIRECTORY,
    IMAGE_DIRECTORY_ENTRY_EXPORT,
    IMAGE_FILE_MACHINE_AMD64,
    IMAGE_SECTION_HEADER,
    IMAGE_FILE_DLL,
    IMAGE_FILE_HEADER,
    IMAGE_BASE_RELOCATION,
    IMAGE_REL_BASED_ABSOLUTE,
    IMAGE_REL_BASED_HIGHLOW,
    IMAGE_REL_BASED_DIR64,
    IMAGE_DIRECTORY_ENTRY_BASERELOC,
    IMAGE_DIRECTORY_ENTRY_TLS,
    IMAGE_DIRECTORY_ENTRY_IMPORT,
    IMAGE_IMPORT_DESCRIPTOR,
};
use winapi::um::synchapi::{
    Sleep,
    WaitForSingleObject};
use winapi::um::sysinfoapi::{GetNativeSystemInfo, SYSTEM_INFO};
use field_offset::offset_of;
use winapi::ctypes::c_void;
use winapi::um::processthreadsapi::{
    GetCurrentProcess,
    CreateRemoteThread};
use winapi::um::memoryapi::{WriteProcessMemory,ReadProcessMemory};
use winapi::vc::vcruntime::ptrdiff_t;
use winapi::um::winbase::{
    IsBadReadPtr, 
    lstrlenW,
    INFINITE};
use std::ffi::CString;
use std::ffi::CStr;
use ntapi::ntpsapi::{
    NtQueryInformationProcess,
    PROCESS_BASIC_INFORMATION, 
    PPROCESS_BASIC_INFORMATION,
    ProcessBasicInformation};
use ntapi::ntpebteb::PEB;
use ntapi::ntpsapi::PEB_LDR_DATA;
use ntapi::ntldr::{LDR_DATA_TABLE_ENTRY,LDR_DATA_TABLE_ENTRY_u1};
use std::ffi::{ OsStr, OsString};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::prelude::OsStringExt;
use std::slice;

// Convert address into function
macro_rules! example {
    ($address:expr, $t:ty) => {
        std::mem::transmute::<*const (), $t>($address as _)
    };
}

// Unhook the following API calls
// OpenProcess -> NtOpenProcess
// VirtualAllocEx-> NtAllocateVirtualMemory
// WriteProcessMemory -> NtWriteVirtualMemory
// CreateRemoteThread -> NtCreateThreadEx
// ReadVirtualMemory ->NtReadVirtualMemory 

// Kernel32.dll::LoadLibraryA
type PLoadLibraryA =  unsafe extern "system" fn (lp_filename: PVOID) -> u32;
// Kernel32.dll::GetProcAddress
type PCustomGetProcAddress =  unsafe extern "system" fn (h_module: HMODULE, lp_proc_name: LPCSTR) -> FARPROC;
// Kernel32.dll::FreeLibary
type PFreeLibary = unsafe extern "system" fn (h_module: HMODULE) -> BOOL;
// Kernel32.dll:VirtualAllocEx
type PVirtualAllocEx = unsafe extern "system" fn (
    h_process: HANDLE, 
    lp_address: LPVOID, 
    dw_size: SIZE_T, 
    fl_allocation_type: DWORD, 
    fl_protect: DWORD) -> LPVOID;
// Kernel32.dll:VirtualFreeEx
type PVirtualFreeEx = unsafe extern "system" fn (
    h_process: HANDLE, 
    lp_address: LPVOID, 
    dw_size: SIZE_T, 
    dw_free_type: DWORD) -> BOOL;
type POpenProcess = unsafe extern "system" fn (
    ProcessHandle: PHANDLE, 
    DesiredAccess: ACCESS_MASK, 
    ObjectAttributes: POBJECT_ATTRIBUTES, 
    ClientId: PCLIENT_ID) -> NTSTATUS;
type PNtWriteVirtualMemory = unsafe extern "system" fn (
    ProcessHandle: HANDLE, 
    BaseAddress: PVOID, 
    Buffer: PVOID, 
    BufferSize: SIZE_T, 
    NumberOfBytesWritten: PSIZE_T) -> NTSTATUS;
type PNtCreateThreadEx = unsafe extern "system" fn (
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
    AttributeList: PPS_ATTRIBUTE_LIST) -> NTSTATUS;
type ExeEntryProc = unsafe extern "system" fn (c_void);

struct FunctionMap {
    //openprocess: POpenProcess,
    //writemem: PNtWriteVirtualMemory,
    //createthread: PNtCreateThreadEx,
    load_libary: PLoadLibraryA,
    get_proc_address: PCustomGetProcAddress,
    free_libary: PFreeLibary,
    virtual_alloc: PVirtualAllocEx,
    virtal_free: PVirtualFreeEx
}

struct PointerList {
    next: Option<Box<PointerList>>,
    address: *mut c_void,
}

struct ExportNameEntry {
    name: LPCSTR,
    idx: WORD,
}

struct MemoryModule {
    header_base: LPVOID,
    code_base: LPVOID,
    h_prochandle: HANDLE,
    h_module: PVOID,
    num_modules: u32,
    initialized: bool,
    is_dll: bool,
    is_relocated: bool,
    functions: FunctionMap,
    export_table: Vec<ExportNameEntry>,
    entry_point: Option<ExeEntryProc>,
    page_size: DWORD,
    blocked_memory: Option<PointerList>,
}

pub const DOS_SIGNATURE: u16 = 0x5a4d;
pub const PE_SIGNATURE: u32 = 0x00004550;
pub const MAX_DLL_NAME: usize = 33;
pub const MAX_DLL_FUNC_NAME: usize = 63;

fn unhook_ntdll()->u32 {
    0
}

unsafe extern "system" fn _default_loadlibrary(lp_filename: PVOID) -> u32 {
    return LoadLibraryA(lp_filename as LPCSTR) as u32
}

// Load the library with createremotethread
unsafe extern "system" fn _remotethread_loadlibrary(
    mem_module: *mut MemoryModule, 
    lp_filename: &str) -> HMODULE {
    let proc_handle = (*mem_module).h_prochandle;
    let virtual_alloc = unsafe {(*mem_module).functions.virtual_alloc};
    let get_proc_addr = unsafe { (*mem_module).functions.get_proc_address };
    
    // Get address to loadlibrary
    let h_kernel = _sneaky_loadlibrary(mem_module, "kernel32.dll");
    let proc_name = CString::new("LoadLibraryA").expect("invalid proc name");
    // TODO: check if this works in remote process
    let loadlibrary_addr = get_proc_addr(h_kernel, proc_name.as_ptr());
    println!("LoadLibraryA proc_addr {:#x}", loadlibrary_addr as u64);

    // write path to remote process
    let dll_path_buf = lp_filename.as_bytes().to_vec();
    let buf_len = dll_path_buf.len()+1;
    // create buffer
    // virtualalloc
    let memory_address = virtual_alloc(
        proc_handle, 
        NULL, 
        buf_len, 
        MEM_COMMIT as u32,
        PAGE_READWRITE);
    // writeprocessmemory
    let mut bytes_written = 0;
    let _status = unsafe {_default_memwrite(
        proc_handle,
        memory_address,
        dll_path_buf.as_ptr() as LPCVOID,
        buf_len as usize,
        &mut bytes_written,
    )};
    let loadlib = example!(loadlibrary_addr, PLoadLibraryA);

    let remote_thread = CreateRemoteThread(
        proc_handle, 
        std::ptr::null_mut(), 
        0, 
        Some(loadlib), 
        memory_address as PVOID, 
        0, 
        std::ptr::null_mut());
    if remote_thread == 0 as HANDLE {
        println!("remote_thread failed");
        return 0 as HMODULE;
    }
    WaitForSingleObject(remote_thread, INFINITE);
    let new_module = _sneaky_loadlibrary(mem_module, lp_filename);
    if new_module == 0 as HMODULE {
        println!("{} failed to load remotely", lp_filename);
        return 0 as HMODULE;
    }
    new_module
}

// 1) Look up from the PEB
//   a) Alloc PROCESS_BASIC_INFORMATION to heap
//   b) NTQueryInformationProcess,  PROCESS_BASIC_INFORMATION
//   c) pPeb = BasicInfo.PebBaseAddress
//   d) Reading the PEB -> ReadProcessMemory(hProcess, pbi->PebBaseAddress, &peb, sizeof(peb), &dwBytesRead)
//   e) Get the exports
unsafe extern "system" fn _sneaky_loadlibrary(
    mem_module: *mut MemoryModule, 
    lp_filename: &str) -> HMODULE {
    let proc_handle = (*mem_module).h_prochandle;
    // Remote Proc PEB
    let mut buffer_size = mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32;
    let mut pbi_buffer: Box<[u8]> = vec![0; buffer_size as usize].into_boxed_slice();
    let mut pbi_ptr = pbi_buffer.as_mut_ptr().cast::<_>() as *mut PROCESS_BASIC_INFORMATION;
    let mut status = NtQueryInformationProcess(
        proc_handle,
        ProcessBasicInformation, 
        pbi_ptr as PVOID, 
        buffer_size, 
        &mut buffer_size);
    if status != 0 {
        println!("NtQueryInformationProcess status {:#x}", status);
        return 0 as HMODULE;
    }
    let peb_ptr = (*pbi_ptr).PebBaseAddress as u64;
    println!("peb_ptr {:#x}", peb_ptr);
    let mut buf = vec![0; mem::size_of::<PEB>()];
    let mut bytes_read: usize = 0;
    // Read PEB
    _default_memread(
        proc_handle,
        peb_ptr as LPCVOID,
        buf.as_mut_ptr() as LPVOID,
        mem::size_of::<PEB>(),
        &mut bytes_read);
    let mut temp = std::ptr::read(buf.as_mut_ptr() as *const _);
    let mut ppeb: &mut PEB = &mut temp;
    let peb_ldr_ptr = (*ppeb).Ldr as u64;
    println!("peb_ldr_ptr {:#x}", peb_ldr_ptr);
    // Read PEB_LDR_DATA 
    let mut ldr_buf = vec![0; mem::size_of::<PEB_LDR_DATA>()];
    _default_memread(
        proc_handle,
        peb_ldr_ptr as LPCVOID,
        ldr_buf.as_mut_ptr() as LPVOID,
        mem::size_of::<PEB_LDR_DATA>(),
        &mut bytes_read);
    let mut ldr_temp = std::ptr::read(ldr_buf.as_mut_ptr() as *const _);
    let mut ppeb_ldr_data: &mut PEB_LDR_DATA = &mut ldr_temp;
    let mem_order_module_list = (*ppeb_ldr_data).InMemoryOrderModuleList;
    let mut list_entry_ptr = mem_order_module_list.Flink as u64;
    let mut list_end = mem_order_module_list.Flink as u64;
    
    let mut ldr_entry_buf = vec![0; mem::size_of::<LDR_DATA_TABLE_ENTRY>()];
    let mut k = 0;
    loop {
        //println!("list_entry_ptr {:#x}", list_entry_ptr);
        _default_memread(
            proc_handle,
            list_entry_ptr as LPCVOID,
            ldr_entry_buf.as_mut_ptr() as LPVOID,
            mem::size_of::<LDR_DATA_TABLE_ENTRY>(),
            &mut bytes_read);
        let mut ldr_entry_temp = std::ptr::read(ldr_entry_buf.as_mut_ptr() as *const _);
        let mut p_ldr_data_table_entry: &mut LDR_DATA_TABLE_ENTRY = &mut ldr_entry_temp;

        let full_name_ptr = (*p_ldr_data_table_entry).FullDllName.Buffer as u64;
        //println!("full_name_ptr {:#x}", full_name_ptr);
        let full_name_len = (*p_ldr_data_table_entry).FullDllName.Length as usize;
        let mut full_name_buf = vec![0; full_name_len];
        _default_memread(
            proc_handle,
            full_name_ptr as LPCVOID,
            full_name_buf.as_mut_ptr() as LPVOID,
            full_name_len,
            &mut bytes_read);
        
        let name_cstring = buff_to_str_w(full_name_buf);
        let name_str = name_cstring.as_c_str().to_str().unwrap();
        // println!("full_name {} {}", name_str, lp_filename);
        if lp_filename.eq_ignore_ascii_case(name_str) {
            let ldr_data_u1 = (*p_ldr_data_table_entry).u1;
            let dll_hmodule = ldr_data_u1.InInitializationOrderLinks.Flink;
            //println!("dll_hmodule {:#x}", dll_hmodule as u64);
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

unsafe extern "system" fn _default_getprocaddress(h_module: HMODULE, lp_proc_name: LPCSTR) -> FARPROC {
    return GetProcAddress(
        h_module, 
        lp_proc_name);
}

unsafe extern "system" fn _default_freelibrary(h_module: HMODULE) -> BOOL {
    return FreeLibrary(h_module);
}

unsafe extern "system" fn _default_virtualalloc(
    h_process: HANDLE, 
    lp_address: LPVOID, 
    dw_size: SIZE_T, 
    fl_allocation_type: DWORD, 
    fl_protect: DWORD) -> LPVOID {
    return VirtualAllocEx(h_process, lp_address, dw_size, fl_allocation_type, fl_protect);    
}

unsafe extern "system" fn _default_virtualfree(
    h_process: HANDLE, 
    lp_address: LPVOID, 
    dw_size: SIZE_T, 
    dw_free_type: DWORD) -> BOOL {
        return VirtualFreeEx(h_process, lp_address, dw_size, dw_free_type);
}

unsafe extern "system" fn _default_memwrite(
    ProcessHandle: HANDLE, 
    BaseAddress: LPVOID, 
    Buffer: LPCVOID, 
    BufferSize: SIZE_T, 
    NumberOfBytesWritten: PSIZE_T) -> NTSTATUS {
    return WriteProcessMemory(
        ProcessHandle, 
        BaseAddress,
        Buffer,
        BufferSize,
        NumberOfBytesWritten,
    );
}

unsafe extern "system" fn _default_memread(
    ProcessHandle: HANDLE, 
    BaseAddress: LPCVOID, 
    Buffer: LPVOID, 
    BufferSize: SIZE_T, 
    NumberOfBytesRead: PSIZE_T) -> BOOL {
    return ReadProcessMemory(
        ProcessHandle, 
        BaseAddress,
        Buffer,
        BufferSize,
        NumberOfBytesRead,
    );
}

pub fn memory_loadlibary(data: PVOID, size: u32)->u32{
    return memory_loadlibrary_ex(
        data, 
        size,
        _default_loadlibrary,
        _default_getprocaddress,
        _default_freelibrary,
        _default_virtualalloc,
        _default_virtualfree,
    );
}
fn check_size(size: u64, expected: u64) -> bool {
    if size < expected {
        println!("check_size failed! {} {}", size, expected);
        return true;
    }
    return false;
}
fn align_value_up(value: u64, alignment: u64) -> u64 {
    return (value + alignment - 1) & !(alignment - 1);
}

// TODO: function too big, refactor later
fn copy_sections(
    data: PVOID, 
    size: usize, 
    nt_ptr: *mut IMAGE_NT_HEADERS,
    file_header: *const IMAGE_FILE_HEADER,
    section_size: u32,
    mem_module: *mut MemoryModule) -> bool {
    let proc_handle = unsafe { (*mem_module).h_prochandle };
    let code_base = unsafe {(*mem_module).code_base};
    let virtual_alloc = unsafe {(*mem_module).functions.virtual_alloc};


    let mut image_first_section_ptr = get_first_section_ptr(nt_ptr, file_header);
    let mut section: IMAGE_SECTION_HEADER = unsafe { *image_first_section_ptr };
    let mut i = 0;
    let num_sections = unsafe {(*file_header).NumberOfSections};
    #[warn(unused_assignments)]
    let mut dest: PVOID = 0 as PVOID;
    
    while i < num_sections {
        // section doesn't contain data in the dll itself, but may define
        // uninitialized data
        if section.SizeOfRawData == 0 {
            if section_size > 0 {
                let section_offset = code_base as u64 + section.VirtualAddress as u64;
                dest = unsafe { virtual_alloc(
                    proc_handle,
                    section_offset as PVOID,
                    section_size as usize,
                    MEM_COMMIT as u32,
                    PAGE_READWRITE,
                )};
                if dest == NULL {
                    return false;
                }
                // Always use position from file to support alignments smaller
                // than page size (allocation above will align to page size).
                dest = (code_base as u64 + section.VirtualAddress as u64) as PVOID;
                unsafe {
                    let physical_addr = section.Misc.PhysicalAddress_mut();
                    (*physical_addr) = (dest as u64 & 0xffffffff) as DWORD;
                }
                // memset(dest, 0, section_size);
                let null_bytes = vec![0; section_size as usize];
                let mut bytes_written = 0;
                let _status = unsafe {_default_memwrite(
                    proc_handle,
                    dest,
                    null_bytes.as_ptr() as LPCVOID,
                    section_size as usize,
                    &mut bytes_written,
                )};
            }
            // section is empty
        } else {
            if check_size(size as u64, (section.PointerToRawData + section.SizeOfRawData) as u64) {
                return false;
            }
            // commit memory block and copy data from dll
            let code_offset = (code_base as u64 + section.VirtualAddress as u64) as PVOID;
            dest = unsafe { virtual_alloc(
                proc_handle,
                code_offset,
                section.SizeOfRawData as usize,
                MEM_COMMIT as u32,
                PAGE_READWRITE,
            )};
            if dest == NULL {
                return false;
            }
            dest = (code_base as u64 + section.VirtualAddress as u64) as PVOID;
            unsafe {
                let physical_addr = section.Misc.PhysicalAddress_mut();
                (*physical_addr) = (dest as u64 & 0xffffffff) as DWORD;
            }
            // memcopy
            let mut bytes_written = 0;
            let data_offset = data as u64 + section.PointerToRawData as u64;
            let _status = unsafe {_default_memwrite(
                proc_handle,
                dest,
                data_offset as LPCVOID,
                section.SizeOfRawData as usize,
                &mut bytes_written,
            )};

        }
        
        image_first_section_ptr = (image_first_section_ptr as u64 +
            mem::size_of::<IMAGE_SECTION_HEADER>() as u64) as *mut IMAGE_SECTION_HEADER;
        section = unsafe { *image_first_section_ptr };
        i = i + 1;
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
    file_header: *const IMAGE_FILE_HEADER) -> *mut IMAGE_SECTION_HEADER {
    let offset_of_first_hdr = unsafe { (*file_header).SizeOfOptionalHeader };
    let field_offset = offset_of!(IMAGE_NT_HEADERS => OptionalHeader).get_byte_offset();
    let image_first_section_ptr = (nt_ptr as u64 + field_offset as u64 +
        offset_of_first_hdr as u64) as *mut IMAGE_SECTION_HEADER;
    image_first_section_ptr
}

fn get_end_of_sections(
    nt_ptr: *mut IMAGE_NT_HEADERS,
    file_header: *const IMAGE_FILE_HEADER,
    section_align: u32) -> u64 {
    let mut last_section_end = 0;
    
    let mut image_first_section_ptr = get_first_section_ptr(nt_ptr, file_header);
    let mut section: IMAGE_SECTION_HEADER = unsafe { *image_first_section_ptr };
    let mut i = 0;
    let num_sections = unsafe {(*file_header).NumberOfSections};
    while i < num_sections {
        let mut end_of_section = 0;
        if section.SizeOfRawData == 0 {
            end_of_section = section.VirtualAddress + section_align;
        } else {
            end_of_section = section.VirtualAddress + section.SizeOfRawData;
        }
        if end_of_section > last_section_end {
            last_section_end = end_of_section;
        }

        image_first_section_ptr = (image_first_section_ptr as u64 +
            mem::size_of::<IMAGE_SECTION_HEADER>() as u64) as *mut IMAGE_SECTION_HEADER;
        section = unsafe { *image_first_section_ptr };
        i = i + 1;
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

fn offset_pointer(data: PVOID, offset: ptrdiff_t) -> PVOID {
    return (data as ptrdiff_t + offset) as PVOID;
}

fn perform_base_relocations(
    nt_ptr: *mut IMAGE_NT_HEADERS, mem_module: *mut MemoryModule, delta: ptrdiff_t) -> bool {
    println!("perform_base_relocations with delta {:#x}", delta);
    let code_base = unsafe {(*mem_module).code_base};
    let proc_handle = unsafe { (*mem_module).h_prochandle };

    // Use original header here
    let directory = get_header_dictionary(
        nt_ptr, IMAGE_DIRECTORY_ENTRY_BASERELOC as usize);
    unsafe {
        if (*directory).Size == 0 {
            return delta == 0;
        }
    }
    let mut relocation_ptr = unsafe { code_base as u64 + (*directory).VirtualAddress as u64 };
    let reloc_size = mem::size_of::<IMAGE_BASE_RELOCATION>();
    println!("reloc_size {:#x}", reloc_size);
    let mut buf = vec![0; reloc_size as usize];
    let mut bytes_read: usize = 0;
    let _result = unsafe {_default_memread(
        proc_handle,
        relocation_ptr as LPCVOID,
        buf.as_mut_ptr() as LPVOID,
        reloc_size,
        &mut bytes_read)};
    if bytes_read != reloc_size {
        println!("failed to read directory!");
        return false;
    }
    unsafe {
        let mut temp = std::ptr::read(buf.as_mut_ptr() as *const _);
        let mut relocation: &mut IMAGE_BASE_RELOCATION = &mut temp;
        while (*relocation).VirtualAddress > 0 {
            // println!("RVA {:#x}", (*relocation).VirtualAddress);
            let dest = code_base as u64 + (*relocation).VirtualAddress as u64;
            let mut rel_info_ptr = offset_pointer(relocation_ptr as PVOID, reloc_size as isize) as u64;
            let mut i = 0;
            let size_of_block = (*relocation).SizeOfBlock;
            let block_len = ((size_of_block as usize-reloc_size) / 2) as usize;
            // println!("# of blocks {}", block_len);
            // println!("rel_into_ptr {:#x}", rel_info_ptr);
            while i < block_len {
                let mut rel_buf = vec![0; mem::size_of::<u16>()];
                let mut reloc_bytes_read = 0;
                _default_memread(
                    proc_handle,
                    rel_info_ptr as LPCVOID,
                    rel_buf.as_mut_ptr() as LPVOID,
                    mem::size_of::<u16>(),
                    &mut reloc_bytes_read);
                let mut rel_into_bytes = std::ptr::read(rel_buf.as_mut_ptr() as *const _);
                let rel_info: &mut u16 = &mut rel_into_bytes;
                let rel_type = (*rel_info >> 12) as u16;
                let rel_offset = *rel_info & 0xfff;
                // println!("rel_info {:#x} {:#x}", rel_type, rel_offset);
                let patch_addr_hl = dest + rel_offset as u64;
                match rel_type {
                    IMAGE_REL_BASED_HIGHLOW => {
                        //println!("IMAGE_REL_BASED_HIGHLOW {:#x}={:#x}", patch_addr_hl, rel_offset);
                        // patch location
                        let mut bytes_written = 0;
                        let delta_buf = ((delta as u32).to_le_bytes()).to_vec();
                        let _status =_default_memwrite(
                            proc_handle,
                            patch_addr_hl as LPVOID,
                            delta_buf.as_ptr() as LPCVOID,
                            mem::size_of::<u32>(),
                            &mut bytes_written,
                        );
                        // TODO: check status
                    },
                    IMAGE_REL_BASED_DIR64 => {
                        //println!("IMAGE_REL_BASED_DIR64 {:#x}={:#x}", patch_addr_hl, rel_offset);
                        let mut bytes_written = 0;
                        let delta_buf = ((delta as u64).to_le_bytes()).to_vec();
                        let _status =_default_memwrite(
                            proc_handle,
                            patch_addr_hl as LPVOID,
                            delta_buf.as_ptr() as LPCVOID,
                            mem::size_of::<u64>(),
                            &mut bytes_written,
                        );
                        // TODO: check status
                    },
                    _=> {},
                };

                rel_info_ptr = rel_info_ptr + mem::size_of::<u16>() as u64;
                i = i + 1;
            }
            //println!("size_of_block {:#x}", size_of_block);
            relocation_ptr = offset_pointer(relocation_ptr as PVOID, size_of_block as isize) as u64;
            // println!("relocation_ptr {:#x}", relocation_ptr, );
            _default_memread(
                proc_handle,
                relocation_ptr as LPCVOID,
                buf.as_mut_ptr() as LPVOID,
                reloc_size,
                &mut bytes_read);
            temp = std::ptr::read(buf.as_mut_ptr() as *const _);
            relocation = &mut temp;
        }
    }
    true
}

unsafe fn buff_to_str_w(buf: Vec<u16>) -> CString {
    let slice = buf.as_slice();
    let full_name_ostr: OsString = OsStringExt::from_wide(slice);
    let full_name_str: &str = full_name_ostr.to_str().unwrap();
    let name_cstring = buff_to_str(full_name_str.as_bytes().to_vec());
    return name_cstring;
}

unsafe fn buff_to_str(buf: Vec<u8>) -> CString{
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
fn build_import_table(
    nt_ptr: *mut IMAGE_NT_HEADERS, mem_module: *mut MemoryModule) -> bool {
    let code_base = unsafe {(*mem_module).code_base};
    let proc_handle = unsafe { (*mem_module).h_prochandle };
    let get_proc_addr = unsafe { (*mem_module).functions.get_proc_address };
    let directory = get_header_dictionary(
        nt_ptr, IMAGE_DIRECTORY_ENTRY_IMPORT as usize);
    unsafe {
        if (*directory).Size == 0 {
            return false;
        }
    }
    let mut import_desc_ptr = unsafe { code_base as u64 + (*directory).VirtualAddress as u64 };
    let import_dir_size =  unsafe { (*directory).Size };
    let import_desc_size = mem::size_of::<IMAGE_IMPORT_DESCRIPTOR>();
    println!("import_dir_size {:#x}", import_dir_size);
    let mut buf = vec![0; import_desc_size as usize];
    let mut bytes_read: usize = 0;
    let _result = unsafe {_default_memread(
        proc_handle,
        import_desc_ptr as LPCVOID,
        buf.as_mut_ptr() as LPVOID,
        import_desc_size,
        &mut bytes_read)};
    if bytes_read != import_desc_size {
        println!("failed to read directory!");
        return false;
    }
    unsafe {
        let mut temp = std::ptr::read(buf.as_mut_ptr() as *const _);
        let mut import_desc: &mut IMAGE_IMPORT_DESCRIPTOR = &mut temp;
        println!("import_desc_ptr {:#x} size {:#x}", 
            import_desc_ptr, code_base as u64 + import_dir_size as u64);
        let import_dir_len = code_base as u64 + (*directory).VirtualAddress as u64 + import_dir_size as u64;
        while import_desc_ptr < import_dir_len && (*import_desc).Name != 0 {
            // println!("Name ptr {:#x}", (*import_desc).Name);
            let name_ptr = code_base as u64 + (*import_desc).Name as u64;
            let mut name_buf = vec![0; MAX_DLL_NAME];
            let mut name_bytes_read: usize = 0;
            _default_memread(
                proc_handle,
                name_ptr as LPCVOID,
                name_buf.as_mut_ptr() as LPVOID,
                MAX_DLL_NAME,
                &mut name_bytes_read);
        
            let name_cstring = buff_to_str(name_buf);
            let name_str = name_cstring.as_c_str().to_str().unwrap();
            //println!("name buf {}", name_str);
            // LoadLibrary
            let mut dll_module = _sneaky_loadlibrary(mem_module, name_str);
            if dll_module == 0 as HMODULE {
                println!("DLL module {} not found, trying to load", name_str);
                dll_module = _remotethread_loadlibrary(mem_module, name_str);
                if dll_module == 0 as HMODULE {
                    println!("DLL module {} not found, trying to load", name_str);
                    return false;
                }
            } 
            println!("DLL module {} {:#x}", name_str, dll_module as u64);
            // TODO: add to list of modules
            let mut thunk_ref:u64 = 0;
            let mut func_ref: u64 = 0;
            let original_first_thunk = (*import_desc).u.OriginalFirstThunk() as u64;
            let first_thunk = (*import_desc).FirstThunk as u64;
            if original_first_thunk != 0 {
                thunk_ref = code_base + original_first_thunk;
                func_ref = code_base + first_thunk;
            } else {
                // no hint table
                thunk_ref = code_base + first_thunk;
                func_ref = code_base + first_thunk;
            }
            // Loop through thunks



            
            import_desc_ptr = import_desc_ptr + import_desc_size as u64;
            // println!("import_desc_ptr {:#x}", import_desc_ptr, );
            _default_memread(
                proc_handle,
                import_desc_ptr as LPCVOID,
                buf.as_mut_ptr() as LPVOID,
                import_desc_size,
                &mut bytes_read);
            temp = std::ptr::read(buf.as_mut_ptr() as *const _);
            import_desc = &mut temp;
        }
    }
    true
}

// TODO: Get debug privileges
fn memory_loadlibrary_ex(
    data: PVOID, 
    size: u32,
    load_libary: PLoadLibraryA,
    get_proc_address: PCustomGetProcAddress,
    free_libary: PFreeLibary,
    virtual_alloc: PVirtualAllocEx,
    virtal_free: PVirtualFreeEx)->u32{

    // Check Size
    if check_size(size as u64, mem::size_of::<IMAGE_DOS_HEADER>() as u64){
        return 0;
    }
    let dos_ptr = data as *mut IMAGE_DOS_HEADER;
    let magic = unsafe {(*dos_ptr).e_magic};
    if DOS_SIGNATURE != magic {
        println!("DOS_SIGNATURE failed!");
        return 0;
    }
    let nt_hdr_offset = unsafe {(*dos_ptr).e_lfanew};
    let nt_ptr = (data as u64 + nt_hdr_offset as u64) as *mut IMAGE_NT_HEADERS;
    if check_size(size as u64, nt_hdr_offset as u64 +
        mem::size_of::<IMAGE_NT_HEADERS>() as u64){
        println!("check_size failed!");
        return 0;
    }
    let pe_sig = unsafe{ (*nt_ptr).Signature };
    if PE_SIGNATURE != pe_sig {
        println!("PE_SIGNATURE failed!");
        return 0;
    }
    let mut file_header = unsafe {(*nt_ptr).FileHeader};
    if file_header.Machine != IMAGE_FILE_MACHINE_AMD64 {
        println!("IMAGE_FILE_MACHINE_AMD64 failed!");
        return 0;
    }
    // Only support section alignments that are a multiple of 2
    let optional_header = unsafe {(*nt_ptr).OptionalHeader};
    let section_align = optional_header.SectionAlignment;
    if section_align & 1 == 1{
        println!("section_align failed!");
        return 0;
    }
    let last_section_end = get_end_of_sections(
        nt_ptr, &file_header, section_align);

    let mut sysinfo: SYSTEM_INFO = unsafe { mem::zeroed() };
    unsafe { GetNativeSystemInfo(&mut sysinfo) };
    let aligned_image_size = align_value_up(
        optional_header.SizeOfImage.into(), 
        sysinfo.dwPageSize as u64);
    if aligned_image_size != align_value_up(last_section_end as u64, sysinfo.dwPageSize as u64) {
        println!("section end is not matching failed!");
        return 0;
    }
    
    // reserve memory for image of library
    let self_handle = unsafe { GetCurrentProcess() }; // TODO: temporary, remove for remote process
    let mut code = unsafe { virtual_alloc(
        self_handle,
        //optional_header.ImageBase as PVOID,
        NULL,
        aligned_image_size as usize,
        (MEM_RESERVE | MEM_COMMIT) as u32,
        PAGE_READWRITE,
    )};

    if code == NULL{
        // try to allocate memory at arbitrary position
        code = unsafe { virtual_alloc(
            self_handle,
            NULL,
            aligned_image_size as usize,
            (MEM_RESERVE | MEM_COMMIT) as u32,
            PAGE_READWRITE,
        )};
        if code == NULL {
            return 0;
        }
    }
    // Memory block may not span 4 GB boundaries (64 bit only)
    let mut blocked_memory = PointerList{
        next: None,
        address: NULL,
    };
    let mut count = 0;
    while code as u64 >> 32 < (code as u64 + aligned_image_size) >> 32 {
        let next = PointerList{
            next: None,
            address: code,
        };
        blocked_memory.next = Some(Box::new(next));
        code = unsafe { virtual_alloc(
            self_handle,
            NULL,
            aligned_image_size as usize,
            (MEM_RESERVE | MEM_COMMIT) as u32,
            PAGE_READWRITE,
        )};
        count = count + 1;
        if code == NULL {
            return 0;
        }
    }
    println!("{} Nodes in blocked_memory", count);
    // End 64bit

    let mut memory_module = MemoryModule{
        header_base: NULL,
        code_base: code,
        h_prochandle: self_handle,
        h_module: NULL,
        num_modules: 0,
        initialized: false,
        is_dll: (file_header.Characteristics & IMAGE_FILE_DLL == 0),
        is_relocated: false,
        functions: FunctionMap {
            load_libary: load_libary,
            get_proc_address: get_proc_address,
            free_libary: free_libary,
            virtual_alloc: virtual_alloc,
            virtal_free: virtal_free,
        },
        export_table: Vec::<ExportNameEntry>::new(),
        entry_point: None,
        page_size: sysinfo.dwPageSize,
        blocked_memory: Some(blocked_memory),
    };

    // commit memory for headers
    if check_size(size as u64, optional_header.SizeOfHeaders as u64){
        return 0;
    }
    let header_mem = unsafe { virtual_alloc(
        self_handle,
        code,
        optional_header.SizeOfHeaders as usize,
        MEM_COMMIT as u32,
        PAGE_READWRITE,
    )};

    // update imagebase
    let old_image_base = optional_header.ImageBase;
    println!("Old ImageBase: {:#x}", old_image_base);
    unsafe {(*nt_ptr).OptionalHeader.ImageBase = code as u64};
    let new_image_base = unsafe {(*nt_ptr).OptionalHeader.ImageBase};
    println!("New ImageBase: {:#x}", new_image_base);

    // copy PE header to code
    let mut bytes_written: usize = 0;
    let _status = unsafe {_default_memwrite(
        self_handle,
        code,
        data as LPCVOID,
        optional_header.SizeOfHeaders as usize,
        &mut bytes_written,
    )};
    // Offset to IMAGE_NT_HEADERS
    memory_module.header_base = (header_mem as u64 + nt_hdr_offset as u64) as LPVOID;

    // copy sections from DLL file block to new memory location
    if !copy_sections(data, size as usize, nt_ptr,
        &mut file_header, section_align, &mut memory_module) {
        println!("failed to copy sections!");
        return 0;
    }
    // adjust base address of imported data
    let location_delta: ptrdiff_t = (new_image_base - old_image_base) as ptrdiff_t;
    if location_delta != 0 {
        memory_module.is_relocated = perform_base_relocations(
            nt_ptr, &mut memory_module, location_delta);
    } else {
        memory_module.is_relocated = true;
    }

    // load required dlls and adjust function table of imports
    if !build_import_table(nt_ptr, &mut memory_module) {
        println!("build_import_table failed!");
        return 0;
    }
    unsafe { Sleep(0x6000) };
    // mark memory pages depending on section headers and release
    // sections that are marked as "discardable"
    // TLS callbacks are executed BEFORE the main loading
    // get entry point of loaded library
    // cleanup
    1
}

fn memory_get_proc_address()->u64{
    0
}
fn memory_free_library()->u32{
    0
}

#[warn(non_snake_case)]
#[no_mangle]
extern "stdcall" fn DllMain(
    h_module: HINSTANCE,
    dw_reason: DWORD,
    _: *const ::std::ffi::c_void) -> BOOL {
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
