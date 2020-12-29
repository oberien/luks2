use luks2::LuksDevice;
use std::{fs::File, io::{Cursor, Read}};

#[test]
fn mk_test() {
    // create test.iso via `fallocate -l 16M test.iso && cryptsetup luksFormat test.iso` with the password "password"
	let path = format!("{}/tests/test.iso", env!("CARGO_MANIFEST_DIR"));
	let mut f = File::open(path).expect("could not open test.iso; did you create it?");
	let mut buf = vec![0; 16 * 1024 * 1024];
	f.read_exact(&mut buf).expect("could not read from test.iso");
	let f = Cursor::new(buf);
	let _luks_device = LuksDevice::from_device(f, b"password", 512).unwrap();
}
