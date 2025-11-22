use core::slice;
use std::fs::File;
use std::io::Read;
use std::{fs, io::BufReader, vec};
use windows_sys::Win32::System::Memory::{
    VirtualAlloc, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
};

use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};
use windows_sys::Win32::System::Threading::CreateThread;
#[repr(C)]
#[derive(Debug)]
struct SectionHeader {
    name: [u8; 8],
    virtual_size: u32,
    virtual_address: u32,
    size_of_raw_data: u32,
    pointer_to_raw_data: u32,
    pointer_to_relocations: u32,
    pointer_to_line_numbers: u32,
    number_of_relocations: u16,
    number_of_line_numbers: u16,
    characteristics: u32,
}
use encoding::all::GB18030;
use encoding::{DecoderTrap, Encoding};
#[no_mangle]
pub extern "C" fn BeaconOutput(_t: u32, arg: *const u8, arg_len: u32) {
    unsafe {
        let str_slice = slice::from_raw_parts(arg, arg_len as usize);
        let ss = {
            if let Ok(output) = String::from_utf8(str_slice.to_vec()) {
                output
            } else if let Ok(output) = GB18030.decode(str_slice, DecoderTrap::Strict) {
                output
            } else {
                String::from_utf8_lossy(str_slice).to_string()
            }
        };
        println!("arg_len: {}, {}", str_slice.len(), ss);
    }
}
#[no_mangle]
pub extern "C" fn BeaconPrintf(_t: u32, arg: *const u8, arg_len: u32) {
    // TODO: use format string
    unsafe {
        let str_slice = slice::from_raw_parts(arg, arg_len as usize);
        let ss = {
            if let Ok(output) = String::from_utf8(str_slice.to_vec()) {
                output
            } else if let Ok(output) = GB18030.decode(str_slice, DecoderTrap::Strict) {
                output
            } else {
                String::from_utf8_lossy(str_slice).to_string()
            }
        };
        println!("arg_len: {}, {}", str_slice.len(), ss);
    }
}
#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
struct CoffSym {
    // union {
    //     char Name[8];
    //     uint32_t value[2];
    // } first;
    first: [u8; 8],
    value: u32,
    section_number: u16,
    typ: u16,
    storage_class: u8,
    number_of_aux_symbols: u8,
}
fn main() -> std::io::Result<()> {
    // println!("Hello, world!");
    let target = "a.o";
    let target = "Q:\\Downloads\\bof-loader\\whoami.x64.o";
    let target = "Q:\\Downloads\\bof-loader\\arp.x64.o";
    let full_content = fs::read(target).unwrap();
    // let f = File::open("a.o").unwrap();
    let f = File::open(target).unwrap();
    let mut reader = BufReader::new(f);

    // FileHeader 0x14
    let mut buf = [0u8; 0x14];
    reader.read_exact(&mut buf)?;
    let num_of_sections = u16::from_le_bytes([buf[2], buf[3]]);
    let pointer_to_symbol_table = u32::from_le_bytes(buf[8..12].try_into().unwrap());
    let number_of_symbols = u32::from_le_bytes(buf[0xc..=0xf].try_into().unwrap());

    let pointer_to_string_table = pointer_to_symbol_table + number_of_symbols * 18;

    let size_of_optional_header = u16::from_le_bytes(buf[0x10..=0x11].try_into().unwrap());
    println!("num_of_sections: 0x{:x}", num_of_sections);
    println!("pointer_to_symbol_table: 0x{:x}", pointer_to_symbol_table);
    println!("number_of_symbols: 0x{:x}", number_of_symbols);
    println!("size_of_optional_header: 0x{:x}", size_of_optional_header);

    println!("pointer_to_string_table: 0x{:x}", pointer_to_string_table);

    // Section headers
    let mut section_headers: Vec<SectionHeader> = vec![];
    let mut section_data: Vec<Vec<u8>> = vec![];
    let mut section_ptrs: Vec<usize> = vec![];
    let mut coff_symbols: Vec<CoffSym> = vec![];
    let mut relocate_num = 0;
    // let mut buf = [0u8;0x28*num_of_sections as usize];
    // let mut buf = vec![0u8;0x28*(num_of_sections-1) as usize];
    for i in 0..(num_of_sections) {
        let mut buf = vec![0u8; 0x28];
        reader.read_exact(&mut buf)?;
        let sec_header =
            unsafe { std::mem::transmute::<[u8; 0x28], SectionHeader>(buf.try_into().unwrap()) };
        println!(
            "section_header ({}): {:?}",
            String::from_utf8_lossy(&sec_header.name),
            &sec_header
        );
        let coff_symbols1: Vec<CoffSym> = full_content[pointer_to_symbol_table as usize
            ..pointer_to_symbol_table as usize + number_of_symbols as usize * 18]
            .chunks(18)
            .map(|x| {
                let coff_sym: CoffSym =
                    unsafe { std::mem::transmute::<[u8; 18], CoffSym>(x.try_into().unwrap()) };
                coff_sym
            })
            .collect();
        coff_symbols.extend_from_slice(&coff_symbols1);
        relocate_num += sec_header.number_of_relocations;

        section_headers.push(sec_header);
    }

    println!("total relocate_num: 0x{:x}", relocate_num);
    let mut function_mapping_idx = 0;
    let function_mapping = unsafe {
        VirtualAlloc(
            std::ptr::null_mut(),
            relocate_num as usize * 8,
            MEM_COMMIT | MEM_RESERVE | 0x00100000,
            PAGE_EXECUTE_READWRITE,
        )
    };

    unsafe {
        std::ptr::copy(
            (BeaconOutput as u64).to_le_bytes().as_ptr(),
            function_mapping.offset(function_mapping_idx * 8) as *mut u8,
            8,
        );
    }
    function_mapping_idx += 1;
    unsafe {
        std::ptr::copy(
            (BeaconPrintf as u64).to_le_bytes().as_ptr(),
            function_mapping.offset(function_mapping_idx * 8) as *mut u8,
            8,
        );
    }
    function_mapping_idx += 1;

    for sec_header in section_headers.iter() {
        if sec_header.size_of_raw_data > 0 {
            let mut buf = vec![0u8; sec_header.size_of_raw_data as usize];
            reader.read_exact(&mut buf)?;
            section_data.push(buf);
        } else {
            section_data.push(vec![]);
        }
    }

    for (i, sec_header) in section_headers.iter().enumerate() {
        if sec_header.size_of_raw_data <= 0 {
            section_ptrs.push(0);
            continue;
        }
        let sec_ptr = unsafe {
            VirtualAlloc(
                std::ptr::null_mut(),
                sec_header.size_of_raw_data as usize,
                MEM_COMMIT | MEM_RESERVE | 0x00100000,
                PAGE_EXECUTE_READWRITE,
            )
        };
        section_ptrs.push(sec_ptr as usize);
        println!(
            "sec_ptr alloc {}: 0x{:x?}",
            String::from_utf8_lossy(&sec_header.name),
            sec_ptr
        );
    }

    let mut i = 0;
    for sec_header in section_headers.iter() {
        for x in full_content[sec_header.pointer_to_relocations as usize
            ..sec_header.pointer_to_relocations as usize
                + sec_header.number_of_relocations as usize * 10]
            .chunks(10)
        {
            let offset = u32::from_le_bytes(x[0..4].try_into().unwrap());
            let symbol_table_index = u32::from_le_bytes(x[4..8].try_into().unwrap());
            let r_type = u16::from_le_bytes(x[8..10].try_into().unwrap());
            println!(
                "relocation: offset: 0x{:x}, symbol_table_index: 0x{:x}, r_type: 0x{:x}",
                offset, symbol_table_index, r_type
            );

            let ss = coff_symbols[symbol_table_index as usize].first;
            let symbol_str = {
                if ss[0] == 0 {
                    let str_offset =
                        pointer_to_string_table + u32::from_le_bytes(ss[4..8].try_into().unwrap());
                    println!("str_offset: 0x{:x}", str_offset);
                    let tmp_str = &full_content[str_offset as usize..];
                    let symbol = String::from_utf8(
                        tmp_str[0..tmp_str.iter().position(|x| x == &0).unwrap_or(0)].to_vec(),
                    )
                    .unwrap();
                    println!("\tfix symbol: {}", symbol);
                    symbol
                } else {
                    String::from_utf8(ss.to_vec()).unwrap()
                }
            };
            println!("== symbol_str: {} {:x?}", symbol_str, &ss);

            // This is Type == 4 relocation code, needed to make global variables to work correctly
            // IMAGE_REL_AMD64_REL32
            if r_type == 4 {
                let cur = &mut section_data[i as usize];
                let old = cur.get(offset as usize..offset as usize + 4).unwrap();
                let old_u32 = u32::from_le_bytes(old.try_into().unwrap());
                println!(
                    "IMAGE_REL_AMD64_REL32 old_u32: {}, ErrorHandler: 0x{:x?}",
                    old_u32, BeaconOutput as usize
                );
                // cur.splice(offset as usize..offset as usize+4, coff_symbols[symbol_table_index as usize].value.to_le_bytes().iter().cloned());
                // 意思是函数在外部，需要加载器来解析
                if coff_symbols[symbol_table_index as usize].section_number == 0 {
                    let mut func_addr = 0;
                    if symbol_str == "__imp_BeaconOutput" {
                        let func = &symbol_str[6..];
                        println!("lib: {}, func: {}", "self", func);
                        unsafe {
                            let diff = function_mapping.offset(0 * 8) as isize
                                - (section_ptrs[i] + offset as usize + 4) as isize;
                            cur.splice(
                                offset as usize..offset as usize + 4,
                                (diff as u32).to_le_bytes(),
                            );
                            println!("__imp_BeaconOutput === write offset(0x{:x}) 0x{:x} => 0x{:x}(0x{:x}-0x{:x})", offset, old_u32, diff, function_mapping.offset(0*8) as isize, (section_ptrs[i] + offset as usize + 4) as isize);
                        }
                    } else if symbol_str == "__imp_BeaconPrintf" {
                        let func = &symbol_str[6..];
                        println!("lib: {}, func: {}", "self", func);
                        unsafe {
                            let diff = function_mapping.offset(1 * 8) as isize
                                - (section_ptrs[i] + offset as usize + 4) as isize;
                            cur.splice(
                                offset as usize..offset as usize + 4,
                                (diff as u32).to_le_bytes(),
                            );
                            println!("__imp_BeaconPrintf === write offset(0x{:x}) 0x{:x} => 0x{:x}(0x{:x}-0x{:x})", offset, old_u32, diff, function_mapping.offset(1*8) as isize, (section_ptrs[i] + offset as usize + 4) as isize);
                        }
                    } else if symbol_str.starts_with("__imp_") {
                        // __imp_MSVCRT$calloc
                        let lib = format!("{}.dll\x00", symbol_str[6..].split("$").nth(0).unwrap());
                        let func = format!("{}\x00", symbol_str[6..].split("$").nth(1).unwrap());
                        let addr = unsafe {
                            let addr = GetProcAddress(
                                LoadLibraryA(lib.as_ptr() as *const _),
                                func.as_ptr() as *const _,
                            );
                            addr
                        };
                        if addr.is_none() {
                            println!("lib: {}, func: {} @0x{:x}", lib, func, 0 as usize);
                            continue;
                        } else {
                            println!(
                                "lib: {}, func: {} @0x{:x}",
                                lib,
                                func,
                                addr.unwrap() as usize
                            );
                        }

                        unsafe {
                            std::ptr::copy(
                                (addr.unwrap() as u64).to_le_bytes().as_ptr(),
                                function_mapping.offset(function_mapping_idx * 8) as *mut u8,
                                8,
                            );

                            let diff = function_mapping.offset(function_mapping_idx * 8) as isize
                                - (section_ptrs[i] + offset as usize + 4) as isize;
                            cur.splice(
                                offset as usize..offset as usize + 4,
                                (diff as u32).to_le_bytes(),
                            );
                            println!(
                                "=== write offset(0x{:x}) 0x{:x} => 0x{:x}(0x{:x}-0x{:x})",
                                offset,
                                old_u32,
                                diff,
                                function_mapping.offset(function_mapping_idx * 8) as isize,
                                (section_ptrs[i] + offset as usize + 4) as isize
                            );
                        }
                        // diff += (section_base - section_ptrs[i] + offset as usize + 4) as u32;
                        // cur.splice(offset as usize..offset as usize+4, [0xde, 0xad, 0xbe, 0xef]);
                        function_mapping_idx += 1;
                    }
                    continue;
                }
                let section_base = section_ptrs
                    [coff_symbols[symbol_table_index as usize].section_number as usize - 1];
                dbg!(section_base);
                // let diff = VirtualAlloc as isize - (section_base  + offset as usize + 4) as isize;
                let mut diff = old_u32 as isize;
                println!(
                    "AA=== write offset(0x{:x}) 0x{:x} => 0x{:x}(0x{:x}-0x{:x})",
                    offset,
                    old_u32,
                    diff,
                    section_base as usize,
                    section_ptrs[i] + offset as usize + 4
                );
                println!("diff: 0x{:x}", diff);
                diff += (section_base as isize
                    - (section_ptrs[i] as isize + offset as isize + 4 as isize));
                println!("diff: 0x{:x}", diff);
                // cur.splice(offset as usize..offset as usize+4, [0xde, 0xad, 0xbe, 0xef]);
                cur.splice(
                    offset as usize..offset as usize + 4,
                    (diff as u32).to_le_bytes(),
                );
                println!(
                    "=== write offset(0x{:x}) 0x{:x} => 0x{:x}(0x{:x}-0x{:x})",
                    offset,
                    old_u32,
                    diff,
                    section_base as usize,
                    section_ptrs[i] + offset as usize + 4
                );
            }
        }
        i += 1;
    }

    for (i, sec_header) in section_headers.iter().enumerate() {
        let buf = &section_data[i];
        let sec_ptr = section_ptrs[i];
        if sec_ptr <= 0 {
            continue;
        }
        unsafe {
            std::ptr::copy(buf.as_ptr(), sec_ptr as *mut u8, buf.len());
        }
        println!(
            "{}: 0x{:x?}",
            String::from_utf8_lossy(&sec_header.name),
            sec_ptr
        );
    }

    for ss in coff_symbols {
        if ss.first[0] != 0 {
            // println!("== symbol name: {} {:x?}, ErrorHandler: {:x?}", String::from_utf8_lossy(&ss.first), &ss, BeaconOutput as usize);
            if String::from_utf8_lossy(&ss.first).starts_with("go") {
                println!("bingo..........");
                // jump to the function
                // section_data[ss.section_number-1][ss.value as usize];
                let executable_memory =
                    (section_ptrs[ss.section_number as usize - 1] + ss.value as usize);
                // Create a thread at the start of the executable shellcode to run it!
                // We use the 'transmute' function to convert our pointer to a function pointer
                use std::{ffi::c_void, ptr};
                unsafe {
                    // asm!("int 3");
                    let executable_memory_pointer: extern "system" fn(*mut c_void) -> u32 =
                        { std::mem::transmute(executable_memory) };

                    let thread_handle = CreateThread(
                        ptr::null_mut(),
                        0,
                        Some(executable_memory_pointer),
                        ptr::null_mut(),
                        0,
                        ptr::null_mut(),
                    );

                    // Wait for our thread to exit to prevent program from closing before the shellcode ends
                    // This is especially relevant for long-running shellcode, such as malware implants
                    windows_sys::Win32::System::Threading::WaitForSingleObject(
                        thread_handle,
                        windows_sys::Win32::System::Threading::INFINITE,
                    );
                }
            }
        }
    }

    dbg!(i);
    Ok(())
}
