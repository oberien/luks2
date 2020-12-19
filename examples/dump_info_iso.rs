//! Setup:
//! 1. Create a file that will be encrytped via LUKS2:
//!    `fallocate -l 1024M luks.iso`
//! 2. Encrypt the file:
//!    `cryptsetup luksFormat luks.iso`
//! 3. Verify that everything worked:
//!    `cryptsetup luksDump luks.iso`

use luks2::{LuksHeader, LuksJson};
use std::{fs::File, io::{Cursor, Read}};

fn main() {
	let mut f = File::open("D:\\Max\\Downloads\\tmp\\luks.iso").expect("could not open luks.iso");

	let mut h = vec![0; 4096];
	f.read_exact(&mut h).expect("could not read from luks.iso");
	let header = LuksHeader::read_from(&mut Cursor::new(&h))
		.expect("could not parse header");
	println!("{}", header);

	let mut j = vec![0; (header.hdr_size - 4096) as usize];
	f.read_exact(&mut j).expect("could not read from luks.iso");
	let j: Vec<u8> = j.iter().map(|b| *b).filter(|b| *b != 0).collect();
	let json = LuksJson::read_from(&mut Cursor::new(&j))
		.expect("could not parse json");
	println!("{:#?}", json);
}