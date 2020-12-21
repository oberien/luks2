use gptman::GPT;
use libc::ioctl;
use luks2::{LuksHeader, LuksJson};
use std::{fs::File, io::{Cursor, Read, Seek, SeekFrom}, os::unix::prelude::AsRawFd};

#[macro_use]
extern crate nix;

fn main() {
    let path = "/dev/nvme0n1";
    let mut drive = File::open(path).expect("could not open drive (are you root?)");
    
    let sector_size = unsafe {
        let mut ss: libc::size_t = 0;
        ioctl(drive.as_raw_fd(), request_code_none!(0x12, 104), &mut ss);
        ss
    } as u64;

    let gpt = GPT::find_from(&mut drive)
        .expect("could not find GPT");
    let partition=  gpt.iter().nth(1)
        .expect("could not get partition entry").1;

    drive.seek(SeekFrom::Start(partition.starting_lba * sector_size))
        .expect("could not seek drive");
    let mut h = vec![0; 4096];
    drive.read_exact(&mut h)
        .expect("could not read luks header");

    let header = LuksHeader::read_from(&mut Cursor::new(h))
        .expect("could not parse luks header");
    println!("{}", header);

    let mut j = vec![0; (header.hdr_size - 4096) as usize];
    drive.read_exact(&mut j)
        .expect("could not read luks json area");
    // remove trailing zeros
    let j: Vec<u8> = j.iter().filter(|b| **b != 0).map(|b| *b).collect();
    
    let json = LuksJson::read_from(&mut Cursor::new(j))
        .expect("could not parse luks json area");
    println!("{:#?}", json);
}
