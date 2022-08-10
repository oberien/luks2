#![cfg_attr(not(feature = "std"), no_std)]

//! This crate defines data structures to interact with a LUKS2 partition.
//!
//! See the `examples/` folder for how to use this with a real partition
//! or an .iso file on Linux and Windows (all examples need to be modified
//! or require creating some files before they work correctly).
//!
//! You'll probably want to compile in release mode most of the time, or else
//! the master key extraction (which happens everytime a `LuksDevice` is
//! created) will take quite a long time.


extern crate alloc;

/// Recover information that was split antiforensically.
pub mod af;

/// Custom error types.
pub mod error;

/// Password input.
#[cfg(feature = "std")]
pub mod password;

use alloc::collections::BTreeMap;
use alloc::{format, vec};
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use self::error::{LuksError, ParseError};
use aes::{Aes128, Aes256, NewBlockCipher};
use hmac::Hmac;
use secrecy::{CloneableSecret, DebugSecret, ExposeSecret, Secret, Zeroize};
use serde::{
    de::{self, Deserializer},
    Deserialize, Serialize,
};
use sha2::Sha256;
use core::{
    cmp::max,
    fmt::{Debug, Display},
    str::FromStr,
};
use acid_io::{self, Cursor, ErrorKind, Read, Seek, SeekFrom};
use bincode::Decode;
use xts_mode::{get_tweak_default, Xts128};

#[macro_use]
extern crate serde_big_array;

big_array! {
    BigArray;
    +184, 7*512
}

/// A LUKS2 header as described
/// [here](https://gitlab.com/cryptsetup/LUKS2-docs/blob/master/luks2_doc_wip.pdf).
#[derive(Decode, PartialEq)]
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
    // #[serde(with = "BigArray")]
    pub label: [u8; 48],
    /// checksum algorithm, "sha256"
    pub csum_alg: [u8; 32],
    /// salt, unique for every header
    // #[serde(with = "BigArray")]
    pub salt: [u8; 64],
    /// UUID of device
    // #[serde(with = "BigArray")]
    pub uuid: [u8; 40],
    /// owner subsystem label or empty
    // #[serde(with = "BigArray")]
    pub subsystem: [u8; 48],
    /// offset from device start in bytes
    pub hdr_offset: u64,
    // must be zeroed
    // #[serde(with = "BigArray")]
    _padding: [u8; 184],
    /// header checksum
    // #[serde(with = "BigArray")]
    pub csum: [u8; 64],
    // Padding, must be zeroed
    // #[serde(with = "BigArray")]
    _padding4069: [u8; 7 * 512],
}

impl LuksHeader {
    /// Attempt to read a LUKS2 header from a reader.
    ///
    /// Note: a LUKS2 header is always exactly 4096 bytes long.
    pub fn from_slice(slice: &[u8]) -> Result<Self, ParseError> {
        let options = bincode::config::legacy().with_big_endian().with_fixed_int_encoding().skip_fixed_array_length();
        let h: Self = bincode::decode_from_slice(slice, options)?.0;
        // let h: BorrowCompat<Self> = bincode::decode_from_slice(slice, options)?.0;
        // let h = h.0;

        // check magic value (must be "LUKS\xba\xbe" or "SKUL\xba\xbe")
        if (h.magic != [0x4c, 0x55, 0x4b, 0x53, 0xba, 0xbe])
            && (h.magic != [0x53, 0x4b, 0x55, 0x4c, 0xba, 0xbe])
        {
            return Err(ParseError::InvalidHeaderMagic);
        }
        // check header version
        if h.version != 2 {
            return Err(ParseError::InvalidHeaderVersion(h.version));
        }

        Ok(h)
    }
}

// implement manually to omit always-zero padding sections
impl Debug for LuksHeader {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{}",
            format!(
                "LuksHeader {{ magic: {:?}, version: {:?}, hdr_size: {:?}, seqid: {:?}, \
			label: {:?}, csum_alg: {:?}, salt: {:?}, uuid: {:?}, subsystem: {:?}, \
			hdr_offset: {:?}, csum: {:?} }}",
                self.magic,
                self.version,
                self.hdr_size,
                self.seqid,
                self.label,
                self.csum_alg,
                self.salt,
                self.uuid,
                self.subsystem,
                self.hdr_offset,
                self.csum
            )
        )
    }
}

impl Display for LuksHeader {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        fn bytes_to_str<'a>(empty_text: &'static str, bytes: &'a [u8]) -> &'a str {
            if bytes.iter().all(|el| *el == 0) {
                empty_text
            } else {
                match core::str::from_utf8(bytes) {
                    Ok(s) => s,
                    Err(_) => "<decoding error>",
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

        write!(
            f,
            "{}",
            format!(
                "LuksHeader {{\n\
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
                magic,
                self.version,
                self.hdr_size,
                self.seqid,
                bytes_to_str("<no label>", &self.label),
                bytes_to_str("<no checksum algorithm>", &self.csum_alg),
                bytes_to_hex_string(&self.salt),
                bytes_to_str("<no uuid>", &self.uuid),
                bytes_to_str("<no subsystem label>", &self.subsystem),
                self.hdr_offset,
                bytes_to_hex_string(&self.csum)
            )
        )
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
        key_size: u32,
        /// The offset from the device start to the beginning of the binary area in bytes.
        #[serde(deserialize_with = "from_str")]
        offset: u64,
        /// The area size in bytes.
        #[serde(deserialize_with = "from_str")]
        size: u64,
    },
}

impl LuksArea {
    /// Returns the encryption algorithm of the area.
    pub fn encryption(&self) -> &String {
        match self {
            LuksArea::raw { encryption, .. } => encryption,
        }
    }

    /// Returns the key size of the area.
    pub fn key_size(&self) -> u32 {
        match self {
            LuksArea::raw { key_size, .. } => *key_size,
        }
    }

    /// Returns the offset of the area.
    pub fn offset(&self) -> u64 {
        match self {
            LuksArea::raw { offset, .. } => *offset,
        }
    }

    /// Returns the size of the area.
    pub fn size(&self) -> u64 {
        match self {
            LuksArea::raw { size, .. } => *size,
        }
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
        hash: String,
    },
}

impl LuksAf {
    /// Returns the number of stripes of the anti-forensic splitter.
    pub fn stripes(&self) -> u16 {
        match self {
            LuksAf::luks1 { stripes, .. } => *stripes,
        }
    }

    /// Returns hash algorithm used for the anti-forensic splitter.
    pub fn hash(&self) -> &String {
        match self {
            LuksAf::luks1 { hash, .. } => hash,
        }
    }
}

/// Stores information on the PBKDF type and parameters of a [`LuksKeyslot`].
#[derive(Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "type")]
// enum variant names must match the JSON values exactly, which are lowercase, so no CamelCase names
#[allow(non_camel_case_types)]
pub enum LuksKdf {
    pbkdf2 {
        /// The salt for the PBKDF in base64 (binary data).
        salt: String,
        /// The hash algorithm for the PKBDF.
        hash: String,
        /// The PBKDF2 iterations count.
        iterations: u32,
    },
    argon2i {
        /// The salt for the PBKDF in base64 (binary data).
        salt: String,
        /// The time cost (in fact the iterations).
        time: u32,
        /// The memory cost in kilobytes. If not available, the keyslot cannot be unlocked.
        memory: u32,
        /// The required nuber of threads (CPU cores number cost). If not available, unlocking
        /// will be slower.
        cpus: u32,
    },
    argon2id {
        /// The salt for the PBKDF in base64 (binary data).
        salt: String,
        /// The time cost (in fact the iterations).
        time: u32,
        /// The memory cost in kilobytes. If not available, the keyslot cannot be unlocked.
        memory: u32,
        /// The required nuber of threads (CPU cores number cost). If not available, unlocking
        /// will be slower.
        cpus: u32,
    },
}

impl LuksKdf {
    /// Returns the salt for the PBKDF in base64 (binary data).
    pub fn salt(&self) -> &String {
        match self {
            LuksKdf::pbkdf2 { salt, .. } => salt,
            LuksKdf::argon2i { salt, .. } => salt,
            LuksKdf::argon2id { salt, .. } => salt,
        }
    }
}

/// The priority of a [`LuksKeyslot`].
#[derive(Debug, Deserialize, Eq, PartialEq, PartialOrd, Ord, Serialize)]
// to match other enum variant names
#[allow(non_camel_case_types)]
pub enum LuksPriority {
    /// The slot should be used only if explicitly stated.
    ignore,
    /// Normal priority keyslot.
    normal,
    /// Tried before normal priority keyslots.
    high,
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
        priority: Option<LuksPriority>,
    },
}

impl LuksKeyslot {
    /// Returns the key size of the key stored in the slot, in bytes.
    pub fn key_size(&self) -> u16 {
        match self {
            LuksKeyslot::luks2 { key_size, .. } => *key_size,
        }
    }

    /// Returns the area of the keyslot.
    pub fn area(&self) -> &LuksArea {
        match self {
            LuksKeyslot::luks2 { area, .. } => area,
        }
    }

    /// Returns the key derivation function of the keyslot.
    pub fn kdf(&self) -> &LuksKdf {
        match self {
            LuksKeyslot::luks2 { kdf, .. } => kdf,
        }
    }

    /// Returns the anti-forensic splitter of the keyslot.
    pub fn af(&self) -> &LuksAf {
        match self {
            LuksKeyslot::luks2 { af, .. } => af,
        }
    }

    /// Returns the priority of the keyslot.
    pub fn priority(&self) -> Option<&LuksPriority> {
        match self {
            LuksKeyslot::luks2 { priority, .. } => priority.as_ref(),
        }
    }
}

/// The LUKS2 user data integrity protection type, an experimental feature which is only included
/// for parsing compatibility.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct LuksIntegrity {
    #[serde(rename(deserialize = "type"))]
    pub integrity_type: String,
    pub journal_encryption: String,
    pub journal_integrity: String,
}

/// The size of a [`LuksSegment`].
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
// to match other enum variant names
#[allow(non_camel_case_types)]
pub enum LuksSegmentSize {
    /// Signals that the size of the underlying device should be used (dynamic resize).
    dynamic,
    /// The size in bytes.
    fixed(u64),
}

/// A segment contains a definition of encrypted areas on the disk containing user data
/// (in LUKS1 mentioned as the user data payload). For a normal LUKS device, there ist only
/// one data segment present.
///
/// Only the `crypt` type is currently used.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
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
        flags: Option<Vec<String>>,
    },
}

impl LuksSegment {
    /// Returns the offset of the segment.
    pub fn offset(&self) -> u64 {
        match self {
            LuksSegment::crypt { offset, .. } => *offset,
        }
    }

    /// Returns the size of the segment.
    pub fn size(&self) -> &LuksSegmentSize {
        match self {
            LuksSegment::crypt { size, .. } => size,
        }
    }

    /// Returns the starting offset for the Initialization Vector.
    pub fn iv_tweak(&self) -> u64 {
        match self {
            LuksSegment::crypt { iv_tweak, .. } => *iv_tweak,
        }
    }

    /// Returns the segment encryption algorithm.
    pub fn encryption(&self) -> &String {
        match self {
            LuksSegment::crypt { encryption, .. } => encryption,
        }
    }

    /// Returns the sector size of the segment.
    pub fn sector_size(&self) -> u16 {
        match self {
            LuksSegment::crypt { sector_size, .. } => *sector_size,
        }
    }

    /// Returns the integrity object of the segment.
    pub fn integrity(&self) -> Option<&LuksIntegrity> {
        match self {
            LuksSegment::crypt { integrity, .. } => integrity.as_ref(),
        }
    }

    /// Returns the flags of the segment.
    pub fn flags(&self) -> Option<&Vec<String>> {
        match self {
            LuksSegment::crypt { flags, .. } => flags.as_ref(),
        }
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
        /// The hash algorithm used by PBKDF2.
        hash: String,
        /// The PBKDF2 iterations count.
        iterations: u32,
    },
}

impl LuksDigest {
    /// Returns the keyslots assigned to the digest.
    pub fn keyslots(&self) -> &Vec<u8> {
        match self {
            LuksDigest::pbkdf2 { keyslots, .. } => keyslots,
        }
    }

    /// Returns the segments assigned to the digest.
    pub fn segments(&self) -> &Vec<u8> {
        match self {
            LuksDigest::pbkdf2 { segments, .. } => segments,
        }
    }

    /// Returns the salt of the digest.
    pub fn salt(&self) -> &String {
        match self {
            LuksDigest::pbkdf2 { salt, .. } => salt,
        }
    }

    /// Returns the digest of the digest object.
    pub fn digest(&self) -> &String {
        match self {
            LuksDigest::pbkdf2 { digest, .. } => digest,
        }
    }

    /// Returns the hash algorithm used by PBKDF2.
    pub fn hash(&self) -> &String {
        match self {
            LuksDigest::pbkdf2 { hash, .. } => hash,
        }
    }

    /// Returns the PBKDF2 iterations count.
    pub fn iterations(&self) -> u32 {
        match self {
            LuksDigest::pbkdf2 { iterations, .. } => *iterations,
        }
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
    pub requirements: Option<Vec<String>>,
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
    pub keyslots: BTreeMap<u8, LuksKeyslot>,
    /// Tokens can optionally include additional metadata. Only included for parsing compatibility.
    pub tokens: BTreeMap<u8, LuksToken>,
    /// Segments describe areas on disk that contain user encrypted data.
    pub segments: BTreeMap<u8, LuksSegment>,
    /// Digests are used to verify that keys decrypted from keyslots are correct. Uses the keys
    /// of keyslots and segments to reference them.
    pub digests: BTreeMap<u8, LuksDigest>,
    /// Persistent header configuration attributes.
    pub config: LuksConfig,
}

impl LuksJson {
    /// Attempt to read a LUKS2 JSON area from a reader. The reader must contain exactly the JSON data
    /// and nothing more.
    pub fn from_slice(slice: &[u8]) -> Result<Self, ParseError> {
        let j: Self = serde_json::from_slice(slice)?;

        // check that the stripes value of all afs are 4000
        let stripes_ok = j.keyslots.iter().all(|(_, k)| k.af().stripes() == 4000u16);
        if !stripes_ok {
            return Err(ParseError::InvalidStripes);
        }

        // check that sector sizes of all segments are valid
        let sector_sizes_valid = j
            .segments
            .iter()
            .all(|(_, s)| vec![512, 1024, 2048, 4096].contains(&s.sector_size()));
        if !sector_sizes_valid {
            return Err(ParseError::InvalidSectorSize);
        }

        // check that keyslots size is aligned to 4096
        if (j.config.keyslots_size % 4096) != 0 {
            return Err(ParseError::KeyslotNotAligned);
        }

        // check that all segments/keyslots references are valid
        let refs_valid = j.digests.iter().all(|(_, d)| {
            d.keyslots().iter().all(|k| j.keyslots.contains_key(k))
                && d.segments().iter().all(|s| j.keyslots.contains_key(s))
        });
        if !refs_valid {
            return Err(ParseError::InvalidReference);
        }

        Ok(j)
    }
}

// taken from https://github.com/serde-rs/json/issues/317#issuecomment-300251188
fn from_str<'de, T, D>(deserializer: D) -> Result<T, D::Error>
where
    T: FromStr,
    T::Err: Display,
    D: Deserializer<'de>,
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
    D: Deserializer<'de>,
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
    D: Deserializer<'de>,
{
    let p = match Option::<i32>::deserialize(deserializer)? {
        Some(pr) => pr,
        None => return Ok(None),
    };
    match p {
        0 => Ok(Some(LuksPriority::ignore)),
        1 => Ok(Some(LuksPriority::normal)),
        2 => Ok(Some(LuksPriority::high)),
        _ => Err(de::Error::custom(format!("invalid priority {}", p))),
    }
}

// helper function to deserialize a LuksSegmentSize
fn deserialize_segment_size<'de, D>(deserializer: D) -> Result<LuksSegmentSize, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    match s.as_str() {
        "dynamic" => Ok(LuksSegmentSize::dynamic),
        x => Ok(LuksSegmentSize::fixed(
            u64::from_str(x).map_err(de::Error::custom)?,
        )),
    }
}

#[derive(Clone)]
pub struct MasterKey(Vec<u8>);

impl Zeroize for MasterKey {
    fn zeroize(&mut self) {
        self.0.zeroize()
    }
}

impl DebugSecret for MasterKey {}

impl CloneableSecret for MasterKey {}

pub type SecretMasterKey = Secret<MasterKey>;

/// A struct representing a LUKS device.
#[derive(Debug)]
pub struct LuksDevice<T: Read + Seek> {
    device: T,
    master_key: SecretMasterKey,
    current_sector: Cursor<Vec<u8>>,
    current_sector_num: u64,
    /// The header read from the device.
    pub header: LuksHeader,
    /// The JSON section read from the device.
    pub json: LuksJson,
    /// The sector size of the device.
    pub sector_size: usize,
    /// The segment used when reading from the device. Defaults to segment 0. Calls to `seek()` will
    /// be considered relative to `active_segment.offset()` if seeking from the start or `active_segment.size()`
    /// if seeking from the end.
    pub active_segment: LuksSegment,
}

impl<T: Read + Seek> LuksDevice<T> {
    /// Creates a `LuksDevice` from a device (i. e. any type that implements [`Read`] and [`Seek`]).
    /// WARNING: this struct internally stores the master key in *user-space* RAM. Please consider the
    /// security implications this may have.
    pub fn from_device(
        mut device: T,
        password: &[u8],
        sector_size: usize,
    ) -> Result<Self, LuksError> {
        // read and parse LuksHeader
        let mut h = vec![0; 4096];
        device.read_exact(&mut h)?;
        let header = LuksHeader::from_slice(&h)?;

        // read and parse LuksJson
        let mut j = vec![0; (header.hdr_size - 4096) as usize];
        device.read_exact(&mut j)?;
        let j: Vec<u8> = j.iter().map(|b| *b).filter(|b| *b != 0).collect();
        let json = LuksJson::from_slice(&j)?;

        let master_key = Self::decrypt_master_key(password, &json, &mut device, sector_size)?;
        let active_segment = json.segments[&0].clone();

        let mut d = LuksDevice {
            device,
            master_key,
            current_sector: Cursor::new(vec![0; 256]),
            current_sector_num: u64::MAX,
            header,
            json,
            sector_size,
            active_segment,
        };
        d.seek(SeekFrom::Start(0))?;

        Ok(d)
    }

    /// Returns the master key of this volume. WARNING: consider the security implications this may have.
    pub fn master_key(&self) -> SecretMasterKey {
        self.master_key.clone()
    }

    /// The size of the active segment in bytes.
    pub fn active_segment_size(&mut self) -> acid_io::Result<u64> {
        Ok(match self.active_segment.size() {
            LuksSegmentSize::fixed(s) => *s,
            LuksSegmentSize::dynamic => {
                let pos_before = self.device.seek(SeekFrom::Current(0))?;
                let end = self.device.seek(SeekFrom::End(0))?;
                self.device.seek(SeekFrom::Start(pos_before))?;
                end - self.active_segment.offset()
            }
        })
    }

    // tries to decrypt the master key with the given password by trying all available keyslots
    fn decrypt_master_key(
        password: &[u8],
        json: &LuksJson,
        device: &mut T,
        sector_size: usize,
    ) -> Result<SecretMasterKey, LuksError>
    where
        T: Read + Seek,
    {
        let mut keyslots: Vec<&LuksKeyslot> = json.keyslots.values().collect();
        keyslots.sort_by_key(|&ks| ks.priority().unwrap_or(&LuksPriority::normal));

        for &ks in keyslots.iter().rev() {
            // reverse to get highest priority first
            match Self::decrypt_keyslot(password, ks, json, device, sector_size) {
                Ok(mk) => return Ok(mk),
                Err(e) => match e {
                    LuksError::InvalidPassword => {}
                    _ => return Err(e),
                },
            }
        }

        Err(LuksError::InvalidPassword)
    }

    // tries to decrypt the specified keyslot using the given password
    // if successful, returns the master key
    fn decrypt_keyslot(
        password: &[u8],
        keyslot: &LuksKeyslot,
        json: &LuksJson,
        device: &mut T,
        sector_size: usize,
    ) -> Result<SecretMasterKey, LuksError>
    where
        T: Read + Seek,
    {
        let area = keyslot.area();
        let af = keyslot.af();

        // only sha256 is supported
        if af.hash() != "sha256" {
            return Err(LuksError::UnsupportedAfHash(af.hash().to_string()));
        }

        // read area of keyslot
        let mut k = vec![0; keyslot.key_size() as usize * af.stripes() as usize];
        device.seek(SeekFrom::Start(area.offset()))?;
        device.read_exact(&mut k)?;

        // compute master key as hash of password
        let mut pw_hash = vec![0; area.key_size() as usize];
        match keyslot.kdf() {
            LuksKdf::argon2i {
                salt,
                time,
                memory,
                cpus,
            }
            | LuksKdf::argon2id {
                salt,
                time,
                memory,
                cpus,
            } => {
                let variant = if let LuksKdf::argon2i { .. } = keyslot.kdf() {
                    argon2::Variant::Argon2i
                } else {
                    argon2::Variant::Argon2id
                };
                let config = argon2::Config {
                    variant,
                    mem_cost: *memory,
                    time_cost: *time,
                    lanes: *cpus,
                    thread_mode: argon2::ThreadMode::Parallel,
                    hash_length: area.key_size(),
                    ..argon2::Config::default()
                };
                let salt = base64::decode(&salt)?;
                pw_hash = argon2::hash_raw(password, &salt, &config)?;
            }
            LuksKdf::pbkdf2 {
                salt,
                hash,
                iterations,
            } => {
                assert_eq!(hash, "sha256");
                let salt = base64::decode(salt)?;
                pbkdf2::pbkdf2::<Hmac<Sha256>>(password, &salt, *iterations, &mut pw_hash);
            }
        }

        // make pw_hash a secret after hashing
        let pw_hash = Secret::new(pw_hash);

        // decrypt keyslot area using the password hash as key
        match area.key_size() {
            32 => {
                let key1 = Aes128::new_from_slice(&pw_hash.expose_secret()[..16]).unwrap();
                let key2 = Aes128::new_from_slice(&pw_hash.expose_secret()[16..]).unwrap();
                let xts = Xts128::<Aes128>::new(key1, key2);
                xts.decrypt_area(&mut k, sector_size, 0, get_tweak_default);
            }
            64 => {
                let key1 = Aes256::new_from_slice(&pw_hash.expose_secret()[..32]).unwrap();
                let key2 = Aes256::new_from_slice(&pw_hash.expose_secret()[32..]).unwrap();
                let xts = Xts128::<Aes256>::new(key1, key2);
                xts.decrypt_area(&mut k, sector_size, 0, get_tweak_default);
            }
            x => return Err(LuksError::UnsupportedKeySize(x)),
        }

        // make k a secret after decryption
        let k = Secret::new(k);

        // merge and hash master key
        let master_key = Secret::new(MasterKey(af::merge(
            &k.expose_secret(),
            keyslot.key_size() as usize,
            af.stripes() as usize,
        )));
        let digest_actual = base64::decode(json.digests[&0].digest())?;
        let mut digest_computed = vec![0; digest_actual.len()];
        let salt = base64::decode(json.digests[&0].salt())?;
        pbkdf2::pbkdf2::<Hmac<Sha256>>(
            &master_key.expose_secret().0,
            &salt,
            json.digests[&0].iterations(),
            &mut digest_computed,
        );

        // compare digests
        if digest_computed == digest_actual {
            Ok(master_key)
        } else {
            Err(LuksError::InvalidPassword)
        }
    }

    // updates the internal state so that current sector is the one with the given number
    // decrypts the sector, performs boundary checks (returns an error if sector_num too small,
    // goes to last sector if sector_num too big)
    fn go_to_sector(&mut self, sector_num: u64) -> acid_io::Result<()> {
        if sector_num == self.current_sector_num {
            return Ok(());
        } else if sector_num
            < (self.active_segment.offset() / self.active_segment.sector_size() as u64)
        {
            return Err(acid_io::Error::new(
                ErrorKind::InvalidInput,
                "tried to seek to position before active segment",
            ));
        }

        let sector_size = self.active_segment.sector_size() as u64;
        let mut max_sector = (self.active_segment_size()? + self.active_segment.offset()) / sector_size;
        if (self.active_segment_size()? % sector_size) != 0 {
            max_sector += 1;
        }

        if sector_num > max_sector {
            return Ok(());
        }

        let sector_pos = SeekFrom::Start(sector_num * sector_size);
        self.device.seek(sector_pos.clone())?;
        let mut sector = vec![0; sector_size as usize];

        if let Err(e) = self.device.read_exact(&mut sector) {
            match e.kind() {
                ErrorKind::UnexpectedEof => {
                    // last sector of device is not of full length
                    // reset position and read again
                    self.device.seek(sector_pos)?;
                    sector.clear();
                    acid_io::copy(&mut self.device, &mut sector)?;
                }
                _ => return Err(e),
            }
        }

        if sector.len() != 0 {
            let iv = sector_num
                - (self.active_segment.offset() / self.active_segment.sector_size() as u64);
            // the iv isn't the index of sector_size sectors, but instead the index of 512-byte sectors
            let iv = iv * (self.active_segment.sector_size() as u64 / 512);
            let iv = get_tweak_default((iv + self.active_segment.iv_tweak()) as u128);
            match self.master_key.expose_secret().0.len() {
                32 => {
                    let key1 =
                        Aes128::new_from_slice(&self.master_key.expose_secret().0[..16]).unwrap();
                    let key2 =
                        Aes128::new_from_slice(&self.master_key.expose_secret().0[16..]).unwrap();
                    let xts = Xts128::<Aes128>::new(key1, key2);
                    xts.decrypt_sector(&mut sector, iv);
                }
                64 => {
                    let key1 =
                        Aes256::new_from_slice(&self.master_key.expose_secret().0[..32]).unwrap();
                    let key2 =
                        Aes256::new_from_slice(&self.master_key.expose_secret().0[32..]).unwrap();
                    let xts = Xts128::<Aes256>::new(key1, key2);
                    xts.decrypt_sector(&mut sector, iv);
                }
                x => {
                    return Err(acid_io::Error::new(
                        ErrorKind::InvalidInput,
                        format!("Unsupported key size: {}", x),
                    ))
                }
            }
        }

        self.current_sector = Cursor::new(sector);
        self.current_sector_num = sector_num;

        Ok(())
    }
}

impl<T: Read + Seek> Read for LuksDevice<T> {
    fn read(&mut self, buf: &mut [u8]) -> acid_io::Result<usize> {
        if self.current_sector.position() == self.active_segment.sector_size() as u64 {
            self.go_to_sector(self.current_sector_num + 1)?;
        }

        self.current_sector.read(buf)
    }
}

impl<T: Read + Seek> Seek for LuksDevice<T> {
    fn seek(&mut self, pos: SeekFrom) -> acid_io::Result<u64> {
        match pos {
            SeekFrom::Start(p) => {
                let sector_size = self.active_segment.sector_size() as u64;
                let p = p + self.active_segment.offset();
                let sector = p / sector_size;
                self.go_to_sector(sector)?;
                self.current_sector.seek(SeekFrom::Start(p % sector_size))?;
            }
            SeekFrom::End(p) => {
                let sector_size = self.active_segment.sector_size() as i128;
                let p = max(0, p); // limit p to non-positive values (for p > 0 we seek to the end)
                let end = self.active_segment_size()? as i128;
                let sector = (end + p as i128) / sector_size;
                if sector < 0 {
                    return Err(acid_io::Error::new(
                        ErrorKind::InvalidInput,
                        "tried to seek to negative sector",
                    ));
                }
                self.go_to_sector(sector as u64)?;

                let target_pos = (end + p as i128) - sector * sector_size;
                self.current_sector
                    .seek(SeekFrom::Start(target_pos as u64))?;
            }
            SeekFrom::Current(p) => {
                let sector_size = self.active_segment.sector_size() as i128;
                let current = self.current_sector_num as i128 * sector_size
                    + self.current_sector.position() as i128;
                let sector = (current + p as i128) / sector_size;
                if sector < 0 {
                    return Err(acid_io::Error::new(
                        ErrorKind::InvalidInput,
                        "tried to seek to negative sector",
                    ));
                }
                self.go_to_sector(sector as u64)?;

                let target_pos = (current + p as i128) - sector * sector_size;
                self.current_sector
                    .seek(SeekFrom::Start(target_pos as u64))?;
            }
        }

        Ok(
            self.current_sector_num * self.active_segment.sector_size() as u64
                + self.current_sector.position(),
        )
    }
}
