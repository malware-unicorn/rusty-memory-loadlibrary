//cargo build --release --target x86_64-pc-windows-gnu --lib
extern crate user32;
extern crate winapi;

use std::ffi::CString;
use user32::MessageBoxA;
use winapi::um::winuser::{MB_OK, MB_ICONINFORMATION};
use winapi::um::libloaderapi::DisableThreadLibraryCalls;
use winapi::um::consoleapi::AllocConsole;
use winapi::um::wincon::FreeConsole;
use winapi::um::winnt::DLL_PROCESS_ATTACH;

#[warn(non_snake_case)]
#[no_mangle]
extern "stdcall" fn DllEntryPoint(
    _h_module: winapi::shared::minwindef::HINSTANCE,
    dw_reason: winapi::shared::minwindef::DWORD,
    _: *const ::std::ffi::c_void,
) -> winapi::shared::minwindef::BOOL {
    if dw_reason == winapi::um::winnt::DLL_PROCESS_ATTACH {
        let lp_text = CString::new("DUMMY! This is CobaltStrike! AHHH").unwrap();
        let lp_caption = CString::new("MessageBox Example").unwrap();

        unsafe {
            MessageBoxA(
                std::ptr::null_mut(),
                lp_text.as_ptr(),
                lp_caption.as_ptr(),
                MB_OK | MB_ICONINFORMATION
            );
        }
    }
    winapi::shared::minwindef::TRUE
}

#[warn(non_snake_case)]
#[no_mangle]
extern "stdcall" fn DllMain(
    _h_module: winapi::shared::minwindef::HINSTANCE,
    dw_reason: winapi::shared::minwindef::DWORD,
    _: *const ::std::ffi::c_void,
) -> winapi::shared::minwindef::BOOL {
    /*if dw_reason == winapi::um::winnt::DLL_PROCESS_ATTACH {
        let lp_text = CString::new("DUMMY! This is CobaltStrike! AHHH").unwrap();
        let lp_caption = CString::new("MessageBox Example").unwrap();

        unsafe {
            MessageBoxA(
                std::ptr::null_mut(),
                lp_text.as_ptr(),
                lp_caption.as_ptr(),
                MB_OK | MB_ICONINFORMATION
            );
        }
    }*/
    if dw_reason == DLL_PROCESS_ATTACH {
        unsafe {
            DisableThreadLibraryCalls(_h_module);
        }
        ::std::thread::spawn(|| {
            if cfg!(debug_assertions) {
                unsafe {
                    AllocConsole();
                }
            }
            // PUT FUNCTION HERE $function();
            unsafe {
                let lp_text = CString::new("DUMMY! This is CobaltStrike! AHHH").unwrap();
                let lp_caption = CString::new("MessageBox Example").unwrap();
                MessageBoxA(
                    std::ptr::null_mut(),
                    lp_text.as_ptr(),
                    lp_caption.as_ptr(),
                    MB_OK | MB_ICONINFORMATION
                );
            }
            if cfg!(debug_assertions) {
                unsafe {
                    FreeConsole();
                }
            }
        });
    }
    winapi::shared::minwindef::TRUE
}
