//! This crate defines data structures to interact with a LUKS2 partition.
//!
//! See `examples/dump_header_win.rs` for how to use this on windows, reading
//! from a disk with a GPT.

use bincode::Options;
use serde::{Deserialize, Serialize, de::{self, Deserializer}};
use std::{
	collections::HashMap,
	fmt::{Debug, Display},
	io::Read,
	str::FromStr
};
#[macro_use]
extern crate serde_big_array;

big_array! {
	BigArray;
	+184, 7*512
}

/// A LUKS2 header as described
/// [here](https://gitlab.com/cryptsetup/LUKS2-docs/blob/master/luks2_doc_wip.pdf).
#[derive(Deserialize, PartialEq, Serialize)]
pub struct LuksHeader {
	/// must be "LUKS\xba\xbe" or "SKUL\xba\xbe"
	pub magic: [u8; 6],
	/// Version 2
	pub version: u16,
	/// header size plus JSON area in bytes
	pub hdr_size: u64,
	/// sequence ID, increased on update
	pub seqid: u64,
	/// ASCII label or empty
	#[serde(with = "BigArray")]
	pub label: [u8; 48],
	/// checksum algorithm, "sha256"
	pub csum_alg: [u8; 32],
	/// salt, unique for every header
	#[serde(with = "BigArray")]
	pub salt: [u8; 64],
	/// UUID of device
	#[serde(with = "BigArray")]
	pub uuid: [u8; 40],
	/// owner subsystem label or empty
	#[serde(with = "BigArray")]
	pub subsystem: [u8; 48],
	/// offset from device start in bytes
	pub hdr_offset: u64,
	// must be zeroed
	#[serde(with = "BigArray")]
	_padding: [u8; 184],
	/// header checksum
	#[serde(with = "BigArray")]
	pub csum: [u8; 64],
	// Padding, must be zeroed
	#[serde(with = "BigArray")]
	_padding4069: [u8; 7*512]
}

impl LuksHeader {
	/// Attempt to read a LUKS2 header from a reader.
	///
	/// Note: a LUKS2 header is always exactly 4096 bytes long.
	pub fn read_from<R: Read>(mut reader: &mut R) -> Result<Self, String> {
		let options = bincode::options()
			.with_big_endian()
			.with_fixint_encoding();
		let h: Self = match options.deserialize_from(&mut reader) {
			Ok(h) => h,
			Err(e) => return Err(format!("{}", e))
		};

		// check magic value (must be "LUKS\xba\xbe" or "SKUL\xba\xbe")
		if (h.magic != [0x4c, 0x55, 0x4b, 0x53, 0xba, 0xbe]) &&
			(h.magic != [0x53, 0x4b, 0x55, 0x4c, 0xba, 0xbe]) {
			return Err("magic value must be \"LUKS\\xba\\xbe\" or \"SKUL\\xba\\xbe\"".to_string());
		}
		// check header version
		if h.version != 2 {
			return Err("invalid header version number, only version 2 is supported".to_string())
		}

		Ok(h)
	}
}

// implement manually to omit always-zero padding sections
impl Debug for LuksHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "{}", format!("LuksHeader {{ magic: {:?}, version: {:?}, hdr_size: {:?}, seqid: {:?}, \
			label: {:?}, csum_alg: {:?}, salt: {:?}, uuid: {:?}, subsystem: {:?}, \
			hdr_offset: {:?}, csum: {:?} }}",
			self.magic, self.version, self.hdr_size, self.seqid, self.label, self.csum_alg,
			self.salt, self.uuid, self.subsystem, self.hdr_offset, self.csum
		))
    }
}

impl Display for LuksHeader {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		fn bytes_to_str<'a>(empty_text: &'static str, bytes: &'a [u8]) -> &'a str {
			if bytes.iter().all(|el| *el == 0) {
				empty_text
			} else {
				match std::str::from_utf8(bytes) {
					Ok(s) => s,
					Err(_) => "<decoding error>"
				}
			}
		}

		fn bytes_to_hex_string(bytes: &[u8]) -> String {
			let mut s = String::with_capacity(bytes.len());
			for b in bytes {
				s += format!("{:02X}", b).as_str()
			}
			s
		}

		let mut magic = String::from_utf8_lossy(&self.magic[..4]).to_string();
		magic += format!("\\x{:x}\\x{:x}", self.magic[4], self.magic[5]).as_str();
		
		write!(f, "{}", format!("LuksHeader {{\n\
			\tmagic: {},\n\
			\tversion: {},\n\
			\theader size: {},\n\
			\tsequence id: {},\n\
			\tlabel: {},\n\
			\tchecksum algorithm: {},\n\
			\tsalt: {},\n\
			\tuuid: {},\n\
			\tsubsystem label: {},\n\
			\theader offset: {},\n\
			\tchecksum: {}\n\
			}}",
			magic, self.version, self.hdr_size, self.seqid,
			bytes_to_str("<no label>", &self.label),
			bytes_to_str("<no checksum algorithm>", &self.csum_alg),
			bytes_to_hex_string(&self.salt), bytes_to_str("<no uuid>", &self.uuid),
			bytes_to_str("<no subsystem label>", &self.subsystem),
			self.hdr_offset, bytes_to_hex_string(&self.csum)
		))
    }
}

/// Information on the allocated area in the binary keyslots area of a [`LuksKeyslot`].
///
/// Only the `raw` type is currently used.
#[derive(Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "type")]
// enum variant names must match the JSON values exactly, which are lowercase, so no CamelCase names
#[allow(non_camel_case_types)]
pub enum LuksArea {
    raw {
		/// The area encryption algorithm, in dm-crypt notation (e. g. "aes-xts-plain64").
		encryption: String,
		/// The area encryption key size.
		key_size: u16,
		/// The offset from the device start to the beginning of the binary area in bytes.
        #[serde(deserialize_with = "from_str")]
		offset: u64,
		/// The area size in bytes.
        #[serde(deserialize_with = "from_str")]
        size: u64
    }
}

/// An anti-forensic splitter of a [`LuksKeyslot`]. See
/// [the LUKS1 spec](https://gitlab.com/cryptsetup/cryptsetup/wikis/Specification)
/// for more information.
///
/// Only the `luks1` type compatible with LUKS1 is currently used.
#[derive(Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "type")]
// enum variant names must match the JSON values exactly, which are lowercase, so no CamelCase names
#[allow(non_camel_case_types)]
pub enum LuksAf {
    luks1 {
		/// The number of stripes, for historical reasons only the 4000 value is supported.
		stripes: u16, // only value of 4000 supported
		/// The hash algorithm used.
        hash: String
    }
}

/// Stores information on the PBKDF type and parameters of a [`LuksKeyslot`].
#[derive(Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "type")]
// enum variant names must match the JSON values exactly, which are lowercase, so no CamelCase names
#[allow(non_camel_case_types)]
pub enum LuksKdf {
    pbkdf2 {
		/// The salt for PBKDF in base64 (binary data).
		salt: String,
		/// The hash algorithm for the PKBDF2.
		hash: String,
		/// The PBKDF2 iterations count.
        iterations: u32
    },
    argon2i {
		/// The salt for PBKDF in base64 (binary data).
		salt: String,
		/// The time cost (in fact the iterations).
		time: u32,
		/// The memory cost in kilobytes. If not available, the keyslot cannot be unlocked.
		memory: u32,
		/// The required nuber of threads (CPU cores number cost). If not available, unlocking
		/// will be slower.
        cpus: u32
    },
    argon2id {
		/// The salt for PBKDF in base64 (binary data).
		salt: String,
		/// The time cost (in fact the iterations).
		time: u32,
		/// The memory cost in kilobytes. If not available, the keyslot cannot be unlocked.
		memory: u32,
		/// The required nuber of threads (CPU cores number cost). If not available, unlocking
		/// will be slower.
        cpus: u32
    }
}

/// The priority of a [`LuksKeyslot`].
#[derive(Debug, Deserialize, PartialEq, Serialize)]
// to match other enum variant names
#[allow(non_camel_case_types)]
pub enum LuksPriority {
	/// The slot should be used only if explicitly stated.
	ignore,
	/// Normal priority keyslot.
	normal,
	/// Tried before normal priority keyslots.
    high
}

/// A keyslot contains information about stored keys – areas, where binary keyslot data are located,
/// encryption and anti-forensic function used, password-based key derivation function (PBKDF) and
/// related parameters.
///
/// Only the `luks2` type is currently used.
#[derive(Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "type")]
// enum variant names must match the JSON values exactly, which are lowercase, so no CamelCase names
#[allow(non_camel_case_types)]
pub enum LuksKeyslot {
    luks2 {
		/// The size of the key stored in the slot, in bytes. 
		key_size: u16,
		/// The allocated area in the binary keyslots area.
		area: LuksArea,
		/// The PBKDF type and parameters used.
		kdf: LuksKdf,
		/// The anti-forensic splitter.
		af: LuksAf,
		/// The keyslot priority (optional).
        #[serde(deserialize_with = "deserialize_priority")]
        #[serde(default)]
        priority: Option<LuksPriority>
    }
}

/// The LUKS2 user data integrity protection type, an experimental feature which is only included
/// for parsing compatibility.
#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub struct LuksIntegrity {
    #[serde(rename(deserialize = "type"))]
    pub integrity_type: String,
    pub journal_encryption: String,
    pub journal_integrity: String
}

/// The size of a [`LuksSegment`].
#[derive(Debug, Deserialize, PartialEq, Serialize)]
// to match other enum variant names
#[allow(non_camel_case_types)]
pub enum LuksSegmentSize {
	/// Signals that the size of the underlying device should be used (dynamic resize).
	dynamic,
	/// The size in bytes.
    fixed(u64)
}

/// A segment contains a definition of encrypted areas on the disk containing user data
/// (in LUKS1 mentioned as the user data payload). For a normal LUKS device, there ist only
/// one data segment present.
///
/// Only the `crypt` type is currently used.
#[derive(Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "type")]
// enum variant names must match the JSON values exactly, which are lowercase, so no CamelCase names
#[allow(non_camel_case_types)]
pub enum LuksSegment {
    crypt {
		/// The offset from the device start to the beginning of the segment in bytes.
        #[serde(deserialize_with = "from_str")]
		offset: u64,
		/// The segment size, see [`LuksSegmentSize`].
        #[serde(deserialize_with = "deserialize_segment_size")]
		size: LuksSegmentSize,
		/// The starting offset for the Initialization Vector.
        #[serde(deserialize_with = "from_str")]
		iv_tweak: u64,
		/// The segment encryption algorithm in dm-crypt notaton (e. g. "aes-xts-plain64").
		encryption: String,
		/// The sector size for the segment (512, 1024, 2048, or 4096 bytes).
		sector_size: u16,
		/// The LUKS2 user data integrity protection type (optional, only included for parsing
		/// compatibility).
        #[serde(default)]
		integrity: Option<LuksIntegrity>,
		/// An array of strings marking the segment with additional information (optional).
        #[serde(default)]
        flags: Option<Vec<String>>
    }
}

/// A digest is used to verify that a key decrypted from a keyslot is correct. Digests are assigned
/// to keyslots and segments. If it is not assigned to a segment, then it is a digest for an unbound
/// key. Every keyslot must have one assigned digest. The key digest also specifies the exact key size
/// for the encryption algorithm of the segment.
///
/// Only the `pbkdf2` type compatible with LUKS1 is used.
#[derive(Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "type")]
// enum variant names must match the JSON values exactly, which are lowercase, so no CamelCase names
#[allow(non_camel_case_types)]
pub enum LuksDigest {
    pbkdf2 {
		/// A list of keyslot numbers that are assigned to the digest.
        #[serde(deserialize_with = "vec_from_str")]
		keyslots: Vec<u8>,
		/// A list of segment numbers that are assigned to the digest.
        #[serde(deserialize_with = "vec_from_str")]
		segments: Vec<u8>,
		/// The binary salt for the digest, in base64.
		salt: String,
		/// The binary digest data, in base64.
		digest: String,
		/// The hash algorithm for PBKDF2.
		hash: String,
		/// The PBKDF2 iterations count.
        iterations: u32
    }
}

/// Global attributes for the LUKS device.
#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub struct LuksConfig {
	/// The JSON area size in bytes. Must match the binary header.
    #[serde(deserialize_with = "from_str")]
	pub json_size: u64,
	/// The binary keyslot area size in bytes. Must be aligned to 4096 bytes.
    #[serde(deserialize_with = "from_str")]
	pub keyslots_size: u64,
	/// An optional list of persistent flags for the device.
    #[serde(default)]
	pub flags: Option<Vec<String>>,
	/// An optional list of additional required featers for the LUKS device.
    #[serde(default)]
    pub requirements: Option<Vec<String>>
}

/// A token is an object that can describe how to get a passphrase to unlock a particular keyslot.
/// It can also contain additional user-defined JSON metadata. No token types are implemented;
/// this is only included for parsing compatibility.
#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub struct LuksToken {}

/// JSON metadata for the device as described
/// [here](https://gitlab.com/cryptsetup/LUKS2-docs/blob/master/luks2_doc_wip.pdf).
#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub struct LuksJson {
	/// Objects describing encrypted keys storage areas.
	pub keyslots: HashMap<u8, LuksKeyslot>,
	/// Tokens can optionally include additional metadata. Only included for parsing compatibility.
	pub tokens: HashMap<u8, LuksToken>,
	/// Segments describe areas on disk that contain user encrypted data.
	pub segments: HashMap<u8, LuksSegment>,
	/// Digests are used to verify that keys decrypted from keyslots are correct. Uses the keys
	/// of keyslots and segments to reference them.
	pub digests: HashMap<u8, LuksDigest>,
	/// Persistent header configuration attributes.
    pub config: LuksConfig
}

impl LuksJson {
	/// Attempt to read a LUKS2 JSON area from a reader.
	pub fn read_from<R: Read>(mut reader: &mut R) -> Result<Self, String> {
		let j: Self = match serde_json::from_reader(&mut reader) {
			Ok(j) => j,
			Err(e) => return Err(format!("{}", e))
		};
		// check that the stripes value of all afs are 4000
		if !j.keyslots.iter().all(|(_, k)| {
			match k {
				LuksKeyslot::luks2 { af, .. } => match af {
					LuksAf::luks1{ stripes, .. } => *stripes == 4000u16
				}
			}
		}) {
			return Err("stripe value of LuksAf must be 4000".to_string());
		}
		// check that sector sizes of all segments are valid
		if !j.segments.iter().all(|(_, s)| {
			match s {
				LuksSegment::crypt { sector_size, .. } => {
					vec![512, 1024, 2048, 4096].contains(sector_size)
				}
			}
		}) {
			return Err("sector size must be 512, 1024, 2048 or 4096".to_string());
		}
		// check that keyslots size is aligned to 4096
		if (j.config.keyslots_size % 4096) != 0 {
			return Err("config keyslots size must be aligned to 4096 bytes".to_string());
		}
		// check that all segments/keyslots references are valid
		if !j.digests.iter().all(|(_, d)| {
			match d {
				LuksDigest::pbkdf2 { keyslots, segments, .. } => {
					keyslots.iter().all(|k| j.keyslots.contains_key(k)) &&
					segments.iter().all(|s| j.keyslots.contains_key(s))
				}
			}
		}) {
			return Err("invalid keyslots/segment reference".to_string());
		}

		Ok(j)
	}
}

// taken from https://github.com/serde-rs/json/issues/317#issuecomment-300251188
fn from_str<'de, T, D>(deserializer: D) -> Result<T, D::Error>
where
    T: FromStr,
    T::Err: Display,
    D: Deserializer<'de>
{
    let s = String::deserialize(deserializer)?;
    T::from_str(&s).map_err(de::Error::custom)
}

// helper function to deserialize a Vec<T> where all elements are serialized as strings,
// basically deserializing a Vec<String> and mapping T::from_str() onto all elements
fn vec_from_str<'de, T, D>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    T: FromStr,
    T::Err: Display,
    D: Deserializer<'de>
{
    let v = Vec::<String>::deserialize(deserializer)?;
    // can't use ? operator in closures (at least I couldn't figure out how) so can't use v.iter().map()
    let mut res = Vec::with_capacity(v.len());
    for s in v {
        res.push(T::from_str(&s).map_err(de::Error::custom)?);
    }
    Ok(res)
}

// helper function to deserialize an Option<LuksPriority>
fn deserialize_priority<'de, D>(deserializer: D) -> Result<Option<LuksPriority>, D::Error>
where
    D: Deserializer<'de>
{
    let p = match Option::<i32>::deserialize(deserializer)? {
        Some(pr) => pr,
        None => return Ok(None)
    };
    match p {
        0 => Ok(Some(LuksPriority::ignore)),
        1 => Ok(Some(LuksPriority::normal)),
        2 => Ok(Some(LuksPriority::high)),
        _ => Err(de::Error::custom(format!("invalid priority {}", p)))
    }
}


// helper function to deserialize a LuksSegmentSize
fn deserialize_segment_size<'de, D>(deserializer: D) -> Result<LuksSegmentSize, D::Error>
where
    D: Deserializer<'de>
{
    let s = String::deserialize(deserializer)?;
    match s.as_str() {
        "dynamic" => Ok(LuksSegmentSize::dynamic),
        x => Ok(
            LuksSegmentSize::fixed(u64::from_str(x).map_err(de::Error::custom)?)
        )
    }
}