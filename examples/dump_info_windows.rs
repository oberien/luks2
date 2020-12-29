use gptman::GPT;
use luks2::*;
use windows_drives::BufferedPhysicalDrive;
use std::io::{Read, Seek, SeekFrom};

fn main() {
	let drive_num = 0;
	let mut drive = BufferedPhysicalDrive::open(drive_num)
		.expect("could not open drive");

	let gpt = GPT::find_from(&mut drive)
		.expect("could not find GPT");
	let partition = gpt.iter().nth(1)
		.expect("could not get partition entry").1;

	let partition = BufferedPhysicalDrive::open_bounded(
		drive_num, (partition.starting_lba, partition.ending_lba)
	).expect("could not open partition");

	println!("Enter password for partition: ");
	let password = password::read().expect("could not read password");

	let sector_size = partition.geometry.bytes_per_sector;
	let mut luks_device = LuksDevice::from_device(
		partition, password.as_bytes(), sector_size as usize
	).expect("could not create luks device");

	println!("{}", luks_device.header);
	println!("{:#?}", luks_device.json);

	let n = 0x10000;
	let mut sector = vec![0; sector_size as usize];
	luks_device.seek(SeekFrom::Start(n)).expect("could not seek luks device");
	luks_device.read_exact(&mut sector).expect("could not read from luks device");
	println!("{:?}", sector);
}
