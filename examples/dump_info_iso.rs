//! Setup:
//! 1. Create a file that will be encrytped via LUKS2:
//!    `fallocate -l 1024M luks.iso`
//! 2. Encrypt the file:
//!    `cryptsetup luksFormat --keyslot-key-size=256 --keyslot-cipher=aes-xts-plain64 --key-size=256 --sector-size=512 luks.iso`
//! 3. Verify that everything worked:
//!    `cryptsetup luksDump luks.iso`

use aes::{Aes128, NewBlockCipher};
use argon2::{self, Config, ThreadMode, Variant};
use hmac::Hmac;
use luks2::*;
use sha2::Sha256;
use std::{fs::File, io::{Cursor, Read, Seek, SeekFrom}};
use xts_mode::{Xts128, get_tweak_default};

fn main() {
	let mut f = File::open("/media/Windows/Max/Downloads/tmp/luks.iso").expect("could not open luks.iso");

	// read and parse LuksHeader
	let mut h = vec![0; 4096];
	f.read_exact(&mut h).expect("could not read header from luks.iso");
	let header = LuksHeader::read_from(&mut Cursor::new(&h))
		.expect("could not parse header");
	println!("{}", header);

	// read and parse LuksJson
	let mut j = vec![0; (header.hdr_size - 4096) as usize];
	f.read_exact(&mut j).expect("could not read json from luks.iso");
	let j: Vec<u8> = j.iter().map(|b| *b).filter(|b| *b != 0).collect();
	let json = LuksJson::read_from(&mut Cursor::new(&j))
		.expect("could not parse json");
	println!("{:#?}", json);

	// read area of keyslot 0
	let ks = &json.keyslots[&0];
	let area = ks.area();
	let af = ks.af();
	let mut k = vec![0; ks.key_size() as usize * af.stripes() as usize];
	f.seek(SeekFrom::Start(area.offset())).expect("could not seek to keyslot 0 area");
	f.read_exact(&mut k).expect("could not read keyslot 0 area");

	// compute master key as argon2i hash of password
	let password = b"password";
	let mut hash = vec![172, 160, 75, 61, 103, 0, 255, 250, 183, 42, 213, 55, 43, 87, 36, 167, 226, 216, 188, 51, 218, 248, 165, 42, 177, 126, 161, 83, 46, 119, 143, 133];
	let kdf = ks.kdf();
	if let LuksKdf::argon2i { salt, time, memory, cpus } = kdf {
		let config = Config {
			variant: Variant::Argon2i,
			mem_cost: *memory,
			time_cost: *time,
			lanes: *cpus,
			thread_mode: ThreadMode::Parallel,
			hash_length: area.key_size(),
			..Config::default()
		};
		let salt = base64::decode(&salt).expect("could not decode salt");
		hash = argon2::hash_raw(password, &salt, &config).expect("could not hash password");
		println!("hash: {:?}", hash);
	}

	// decrypt keyslot area using the password hash as key
	let key1 = Aes128::new_varkey(&hash[..16]).unwrap();
	let key2 = Aes128::new_varkey(&hash[16..]).unwrap();
	let xts = Xts128::<Aes128>::new(key1, key2);
	let sector_size = 512;
	xts.decrypt_area(&mut k, sector_size, (area.offset() as usize / sector_size) as u128,
		get_tweak_default);

	// merge master key
	let mut master_key = vec![0; ks.key_size() as usize];
	afsplitter::merge(&k, &mut master_key, ks.key_size() as usize, af.stripes() as usize);

	// hash master key
	let digest_actual = base64::decode(json.digests[&0].digest()).expect("could not decode actual digest");
	let mut digest_computed = vec![0; digest_actual.len()];
	let salt = base64::decode(json.digests[&0].salt()).expect("could not decode digest salt");
	pbkdf2::pbkdf2::<Hmac<Sha256>>(&master_key, &salt, json.digests[&0].iterations(), &mut digest_computed);

	// compare digests
	println!("actual digest: {:?}", digest_actual);
	println!("computed digest: {:?}", digest_computed)
}