#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(dead_code)]
#![cfg(windows)]


extern crate rand;

use winapi::*;
use std::ffi::CString;
use std::str;

fn randomString() -> String {
    use privatedirectory::rand::Rng;

    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    const PASSWORD_LEN: usize = 64;
    let mut rng = rand::thread_rng();

    let password: String = (0..PASSWORD_LEN)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect();

    //println!("{:?}", password);
    return password;
}

#[cfg(windows)]
pub fn getUIDUser(clientSocket: SOCKET) -> String {
    let mut directoryRandom = randomString();
    //ws2_32::send(clientSocket, c_to_print.as_ptr(),len_us , 0);
    unsafe {
        loop {
            let c_to_print = CString::new("Please enter your UID (or empty if you don't have): \n")
                .expect("CString::new failed");
            let len = libc::strlen(c_to_print.as_ptr());
            let len_us: i32 = len as i32;
            let mut tmp_us_send: u32 = 0 as u32;
            let mut tmp_us_read: u32 = 0 as u32;

            kernel32::WriteFile(
                clientSocket as HANDLE,
                c_to_print.as_ptr() as LPCVOID,
                len_us as DWORD,
                &mut tmp_us_send,
                0 as LPOVERLAPPED,
            );

            let mut bufferRecv: [c_char; 65] = [0; 65];
            let mut isAlpha64 = true;

            let ret = kernel32::ReadFile(
                clientSocket as HANDLE,
                bufferRecv.as_mut_ptr() as LPVOID,
                bufferRecv.len() as u32,
                &mut tmp_us_read,
                0 as LPOVERLAPPED,
            );
            if ret == 0 {
                ws2_32::closesocket(clientSocket);
                return directoryRandom;
            }
            //buf[0..tmp_us_read]
            if let Some((last, elements)) = bufferRecv.split_last() {
                if elements[0] == 10 && tmp_us_read == 1 {
                    let stri = format!("Your UID is {} and is valid for 10 minutes only.\nPlease save it if you want to retrieve your data for your next connection\n", directoryRandom);
                    let c_to_print = CString::new(stri).expect("CString::new failed");
                    let len = libc::strlen(c_to_print.as_ptr());
                    let len_us: i32 = len as i32;
                    kernel32::WriteFile(
                        clientSocket as HANDLE,
                        c_to_print.as_ptr() as LPCVOID,
                        len_us as DWORD,
                        &mut tmp_us_send,
                        0 as LPOVERLAPPED,
                    );
                    break;
                }
                //Can be a problem if end of line is \r\n                
                if *last != 10 || tmp_us_read != 65 {
                    isAlpha64 = false;
                    //println!("par ici {:?} {:?}", *last, tmp_us_read);
                }

                if isAlpha64 == true {
                    for c in elements.iter() {
                        if !((*c >= 97 && *c <= 122)
                            || (*c >= 65 && *c <= 90)
                            || (*c >= 48 && *c <= 57))
                        {
                            isAlpha64 = false;
                            //println!("par la");
                            break;
                        }
                    }
                }

                if isAlpha64 == false {
                    let c_to_print = CString::new("Expecting 64 alphabetical chars exactly \n")
                        .expect("CString::new failed");
                    let len = libc::strlen(c_to_print.as_ptr());
                    let len_us: i32 = len as i32;
                    kernel32::WriteFile(
                        clientSocket as HANDLE,
                        c_to_print.as_ptr() as LPCVOID,
                        len_us as DWORD,
                        &mut tmp_us_send,
                        0 as LPOVERLAPPED,
                    );
                } else {
                    let my_slice = &bufferRecv[0..64];
                    //let my_string = my_slice.into_string().unwrap();
                    let u8slice = &*(my_slice as *const _ as *const [u8]);
                    directoryRandom = String::from(str::from_utf8(u8slice).unwrap());

                    //.to;//c_to_print.into_string().unwrap();
                    break;
                }
            }
        }
    }

    return directoryRandom.clone();
}
