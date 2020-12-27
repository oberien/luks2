use luks2::LuksDevice;
use std::io::Cursor;

fn main() {
	// example.iso was generated via `fallocate -l 1M example.iso && cryptsetup luksFormat example.iso` with the password "password"
	let f = Cursor::new(include_bytes!("example.iso"));

	let luks_dev = LuksDevice::from_device(f, b"password", 512)
		.expect("could not create device");

	println!("{}", luks_dev.header);
	println!("{:#?}", luks_dev.json);
}
