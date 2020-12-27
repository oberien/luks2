use luks2::LuksDevice;
use std::io::Cursor;

#[test]
fn mk_test() {
    // test.iso was generated via `fallocate -l 1M test.iso && cryptsetup luksFormat test.iso` with the password "password"
	let f = Cursor::new(include_bytes!("test.iso"));
	let _luks_device = LuksDevice::from_device(f, b"password", 512).unwrap();
}
