use libc::ioctl;
use luks2::*;
use std::{fs::File, os::unix::prelude::AsRawFd};

#[macro_use]
extern crate nix;

fn main() {
	let path = "/dev/nvme0n1p2";
	let partition = File::open(path).expect("could not open partition (are you root?)");
	
	let sector_size = unsafe {
		let mut ss: libc::size_t = 0;
		ioctl(partition.as_raw_fd(), request_code_none!(0x12, 104), &mut ss);
		ss
	};

	println!("Enter password for partition: ");
	let password = password::read().expect("could not read password");

	let luks_device = LuksDevice::from_device(partition, password.as_bytes(), sector_size)
		.expect("could not create luks device");

	println!("{}", luks_device.header);
	println!("{:#?}", luks_device.json);
}
