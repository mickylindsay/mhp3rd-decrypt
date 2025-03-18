use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};

// Decoding/encoding table and encryption/decryption keys courtesy of https://github.com/svanheulen/mhef/blob/8a5132fb7024103ba6271371b81060a55a437651/mhef/psp.py#L79
const DECRYPT_TABLE: [u8; 256] = [
    0xCB, 0x96, 0x85, 0xA6, 0x5F, 0x3E, 0xAB, 0x03, 0x50, 0xB7, 0x9C, 0x5C, 0xB2, 0x40, 0xEF, 0xF6,
    0xFF, 0x61, 0x15, 0x29, 0xA2, 0xF1, 0xEC, 0x52, 0x35, 0x28, 0xD9, 0x68, 0x24, 0x36, 0xC4, 0x74,
    0x26, 0xE2, 0xD5, 0x8C, 0x47, 0x4D, 0x2C, 0xFA, 0x86, 0x66, 0xC1, 0x4F, 0x0B, 0x81, 0x5B, 0x1B,
    0xC0, 0x0A, 0xFD, 0x17, 0xA4, 0xA9, 0x6D, 0x63, 0xAD, 0xF3, 0xF4, 0x6E, 0x8D, 0x89, 0x14, 0xDD,
    0x59, 0x87, 0x4A, 0x30, 0xCE, 0xFE, 0x3F, 0x7E, 0x06, 0x49, 0xA5, 0x04, 0x5E, 0xD0, 0xDE, 0xE8,
    0x0F, 0xD4, 0x13, 0x1F, 0xBA, 0xB9, 0x69, 0x71, 0x3D, 0xE4, 0xDC, 0x58, 0x90, 0x34, 0x3A, 0x3C,
    0xCA, 0x10, 0x76, 0xC7, 0xC8, 0x45, 0x33, 0xC3, 0x92, 0x1D, 0x2B, 0x1C, 0x8F, 0x6F, 0x05, 0x07,
    0x38, 0x57, 0x51, 0xD6, 0xDA, 0x2D, 0xB3, 0xC6, 0x2E, 0x64, 0x32, 0x1E, 0x43, 0xB1, 0x5D, 0xE1,
    0xBB, 0x8E, 0x9D, 0x72, 0x77, 0xF2, 0x27, 0xC9, 0x7F, 0x9E, 0xAA, 0x6A, 0x2F, 0x6C, 0xF9, 0x48,
    0xE7, 0xA0, 0x09, 0x56, 0xB8, 0xBD, 0x20, 0x41, 0xCD, 0x95, 0x80, 0xD7, 0x23, 0x0C, 0x42, 0xE5,
    0xAE, 0x8B, 0x7D, 0xBC, 0x54, 0x39, 0xBF, 0x65, 0x01, 0x88, 0xE0, 0x7B, 0xB6, 0x16, 0x18, 0x4B,
    0xCC, 0x22, 0x5A, 0xB5, 0xEB, 0xFC, 0xF8, 0x9B, 0x4E, 0xE6, 0xA8, 0xBE, 0x67, 0x73, 0x97, 0x94,
    0x00, 0x62, 0xB4, 0xD2, 0x21, 0x25, 0x11, 0x82, 0xDB, 0x93, 0x02, 0x84, 0x7C, 0xD3, 0xB0, 0xA3,
    0x91, 0xA7, 0xF7, 0x55, 0x70, 0x7A, 0x08, 0x75, 0x8A, 0x53, 0x79, 0xFB, 0x9F, 0x46, 0xF5, 0x83,
    0xD8, 0x0E, 0xE9, 0xED, 0x12, 0xD1, 0xDF, 0xF0, 0x37, 0x2A, 0x44, 0x19, 0x9A, 0x31, 0xCF, 0xA1,
    0xAF, 0xE3, 0x3B, 0x1A, 0x4C, 0x78, 0xC2, 0x60, 0xEE, 0x98, 0x6B, 0x0D, 0x99, 0xEA, 0xC5, 0xAC,
];

const DEFAULT_KEY: [u16; 2] = [0x2345, 0x7F8D];
const KEY_MODULO: [u16; 2] = [0xFFD9, 0xFFF1];

// Useful if I ever want to reconstruct the BIN file
fn _generate_encrypt_table(decrypt_table: [u8; 256]) -> [u8; 256] {
    let mut encrypt_table: [u8; 256] = [0u8; 256];
    for (i, val) in decrypt_table.iter().enumerate() {
        encrypt_table[*val as usize] = i as u8;
    }
    return encrypt_table;
}

fn initialize_key(seed: u32) -> u32 {
    let mut key1 = (seed >> 16) as u16;
    if key1 == 0 {
        key1 = DEFAULT_KEY[0];
    }
    let mut key2 = (seed & 0xFFFF) as u16;
    if key2 == 0 {
        key2 = DEFAULT_KEY[1];
    }
    return ((key1 as u32) << 16) + key2 as u32;
}
fn next_key(key: u32) -> u32 {
    let key1 = ((key >> 16) * DEFAULT_KEY[0] as u32) % KEY_MODULO[0] as u32;
    let key2 = ((key & 0xFFFF) * DEFAULT_KEY[1] as u32) % KEY_MODULO[1] as u32;
    return ((key1 as u32) << 16) + key2 as u32;
}

fn translate_buffer(buffer: [u8; 4]) -> u32 {
    return (DECRYPT_TABLE[buffer[0] as usize] as u32)
        + ((DECRYPT_TABLE[buffer[1] as usize] as u32) << 8)
        + ((DECRYPT_TABLE[buffer[2] as usize] as u32) << 16)
        + ((DECRYPT_TABLE[buffer[3] as usize] as u32) << 24);
}

fn header_to_file_format(header: &[u8]) -> &'static str {
    match header {
        [0x89, 0x50, 0x4E, 0x47] => "png",
        [0x47, 0x49, 0x46, 0x38] => "gif",
        [0x52, 0x49, 0x46, 0x46] => "wav",
        [0x4D, 0x49, 0x47, 0x2e] => "gim", //PSP image format https://wiki.vg-resource.com/GIM. Open with Noesis
        [0x4D, 0x57, 0x6F, 0x33] => "mwo3", // Code overlay? ovl file is referenced in the data? https://gtamods.com/wiki/PS2_Code_Overlay
        [0x2E, 0x54, 0x4D, 0x48] => "tmh", // Some kind of texture file? https://forums.ps2dev.org/viewtopic.php?t=12427
        _ => "bin",
    }
}

fn decrypt_file(in_file: &mut File, toc: &Vec<u32>, index: usize) {
    let mut out_file = File::create(format!("out/{}.bin", index)).unwrap();
    let mut buffer: [u8; 1024] = [0; 1024];

    let start = toc[index];
    let mut remaining_bytes = ((toc[index + 1] - start) * 2048) as usize;
    let mut key = initialize_key(start);

    in_file
        .seek(SeekFrom::Start((start * 2048) as u64))
        .expect("Invalid seek to position of input file.");

    while remaining_bytes > 0 {
        let read_size = in_file.read(&mut buffer).unwrap();
        remaining_bytes = remaining_bytes - read_size;
        for i in (0..read_size).step_by(4) {
            key = next_key(key);
            let data = translate_buffer(buffer[i..i + 4].try_into().unwrap()) ^ key;
            buffer[i..i + 4].copy_from_slice(&data.to_le_bytes());
        }
        out_file.write_all(&buffer).unwrap();
    }
}

fn rename_file(file_index: usize) {
    let src = format!("out/{}.bin", file_index);
    let mut decrypted_file = File::open(src.clone()).unwrap();
    let mut header_buffer: [u8; 4] = [0; 4];
    decrypted_file.read(&mut header_buffer).unwrap();
    drop(decrypted_file); // manually close file, as will moved based on filetype
    let format = header_to_file_format(&header_buffer[0..4]);
    if format == "bin" {
        // Printing the first 4 bytes of files not yet classified
        println!("bin\t{}\t{:X?}", file_index, header_buffer);
    }
    let filename = format!("out/{}.{}", file_index, format);
    fs::rename(src, filename).unwrap();
}

fn main() {
    // println!("{:X?}", generate_encrypt_table(DECRYPT_TABLE));

    fs::create_dir_all("out").unwrap();
    let mut key = initialize_key(0);
    let mut out_file = File::create("out/toc.bin").unwrap();
    let mut in_file = File::open("DATA.BIN").unwrap();
    let mut buffer: [u8; 4] = [0; 4];

    let mut prev = 0x0;
    let mut file_indexes = Vec::new();

    // Keep reading 4 byte values until they stop increasing.
    // That is the end of the Table of Contents
    loop {
        let _size = in_file.read(&mut buffer).unwrap();

        key = next_key(key);
        let data = translate_buffer(buffer) ^ key;

        if data < prev {
            break;
        }
        file_indexes.push(data);
        out_file.write_all(&data.to_le_bytes()).unwrap();
        prev = data
    }

    for index in 0..file_indexes.len() - 1 {
        decrypt_file(&mut in_file, &file_indexes, index);
        rename_file(index);
    }
}
