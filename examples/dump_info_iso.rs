use luks2::LuksDevice;
use std::{fs::File, io::{Cursor, Read}};

fn main() {
	// create example.iso via `fallocate -l 16M example.iso && cryptsetup luksFormat example.iso` with the password "password"
	let path = format!("{}/examples/example.iso", env!("CARGO_MANIFEST_DIR"));
	let mut f = File::open(path).expect("could not open example.iso; did you create it?");
	let mut buf = vec![0; 16 * 1024 * 1024];
	f.read_exact(&mut buf).expect("could not read from example.iso");
	let f = Cursor::new(buf);

	let luks_dev = LuksDevice::from_device(f, b"password", 512)
		.expect("could not create device");

	println!("{}", luks_dev.header);
	println!("{:#?}", luks_dev.json);
}
