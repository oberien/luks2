#[test]
fn parse_json() {
	use luks2::*;
	use std::{collections::HashMap, io::Cursor};

	let mut k = HashMap::new();
	k.insert(0, LuksKeyslot::luks2 {
		key_size: 32,
		area: LuksArea::raw {
			encryption: String::from("aes-xts-plain64"),
			key_size: 32,
			offset: 32768,
			size: 131072
		},
		kdf: LuksKdf::argon2i {
			salt: String::from("z6vz4xK7cjan92rDA5JF8O6Jk2HouV0O8DMB6GlztVk="),
			time: 4,
			memory:
			235980,
			cpus: 2
		},
		af: LuksAf::luks1 {
			stripes: 4000,
			hash: String::from("sha256")
		},
		priority: None
	});
	k.insert(1, LuksKeyslot::luks2 {
		key_size: 32,
		area: LuksArea::raw {
			encryption: String::from("aes-xts-plain64"),
			key_size: 32,
			offset: 163840,
			size: 131072
		},
		kdf: LuksKdf::pbkdf2 {
			salt: String::from("vWcwY3rx2fKpXW2Q6oSCNf8j5bvdJyEzB6BNXECGDsI="),
			hash: String::from("sha256"),
			iterations: 1774240
		},
		af: LuksAf::luks1 {
			stripes: 4000,
			hash: String::from("sha256")
		},
		priority: None
	});

	let mut t = HashMap::new();
	t.insert(0, LuksToken {});

	let mut s = HashMap::new();
	s.insert(0, LuksSegment::crypt {
		offset: 4194304,
		size: LuksSegmentSize::dynamic,
		iv_tweak: 0,
		encryption: String::from("aes-xts-plain64"),
		sector_size: 51266,
		integrity: None,
		flags: None
	});

	let mut d = HashMap::new();
	d.insert(0, LuksDigest::pbkdf2 {
		keyslots: vec![0, 1],
		segments: vec![0],
		salt: String::from("G8gqtKhS96IbogHyJLO+t9kmjLkx+DM3HHJqQtgc2Dk="),
		digest: String::from("C9JWko5m+oYmjg6R0t/98cGGzLr/4UaG3hImSJMivfc="),
		hash: String::from("sha256"),
		iterations: 110890
	});

	let expected = LuksJson {
		keyslots: k,
		tokens: t,
		segments: s,
		digests: d,
		config: LuksConfig {
			json_size: 12288,
			keyslots_size: 4161536,
			flags: Some(vec![String::from("allow-discards")]),
			requirements: None
		} 
	};

	let data = include_bytes!("test.json");
	let parsed = LuksJson::from_slice(data).unwrap();
	
	assert_eq!(parsed, expected)
}
