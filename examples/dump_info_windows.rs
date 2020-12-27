use gptman::GPT;
use luks2::*;
use windows_drives::BufferedPhysicalDrive;
use std::io::{Cursor, Read, Seek, SeekFrom};

fn main() {
	let drive_num = 0;
	let mut drive = BufferedPhysicalDrive::open(drive_num)
		.expect("could not open drive");

	let gpt = GPT::find_from(&mut drive)
		.expect("could not find GPT");
	let partition=  gpt.iter().nth(1)
		.expect("could not get partition entry").1;

	drive.seek(SeekFrom::Start(partition.starting_lba * drive.geometry.bytes_per_sector as u64))
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

	drive.close();
}
