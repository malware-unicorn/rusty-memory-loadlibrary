mod lib;
use crate::lib::*;
use std::fs;
use std::fs::File;
use std::io::Read;
use winapi::ctypes::c_void;

fn get_file_as_byte_vec(filename: &String) -> Option<Vec<u8>> {
    println!("get_file_as_byte_vec ...");
    let mut f = match File::open(&filename) {
        Ok(file) => file,
        Err(_err) => return None,
    };
    let metadata = match fs::metadata(&filename){
        Ok(m) => m,
        Err(_err) => return None,
    };
    let mut buffer = vec![0; metadata.len() as usize];
    match f.read(&mut buffer){
        Ok(_) => return Some(buffer),
        Err(_err) => return None,
    };
}

fn read_payload() -> Option<Vec<u8>> {
    println!("read_payload ...");
    let filename = String::from("somedll.dll");
    match get_file_as_byte_vec(&filename){
        Some(buffer) => return Some(buffer),
        None => {
            println!("get_file_as_byte_vec failed");
            return None
        },
    };
}

fn main() {
    let mut data = match read_payload() {
        Some(buffer)=> buffer,
        None => {
            println!("failed to retrieve file data");
            return;
        }
    };
    let handle = memory_loadlibary(data.as_mut_ptr() as *mut c_void, data.len() as u32);
    if handle == 0 {
        println!("loading failed");
    }
    println!("Hello, world!");
}
