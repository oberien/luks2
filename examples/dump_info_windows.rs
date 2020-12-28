use gptman::GPT;
use luks2::*;
use windows_drives::BufferedPhysicalDrive;

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
	let luks_device = LuksDevice::from_device(
		partition, password.as_bytes(), sector_size as usize
	).expect("could not create luks device");

	println!("{}", luks_device.header);
	println!("{:#?}", luks_device.json);
}
