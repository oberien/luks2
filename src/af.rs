use sha2::{Digest, Sha256};

fn xor_block(src1: &[u8], src2: &[u8], dst: &mut [u8], n: usize) {
	for j in 0..n {
		dst[j] = src1[j] ^ src2[j];
	}
}

fn diffuse(src: &[u8], dst: &mut [u8], size: usize) {
	let mut sha256 = Sha256::new();
	let digest_size = Sha256::output_size();
	let blocks = size / digest_size;
	let padding = size % digest_size;

	for i in 0..blocks {
		sha256.update((i as u32).to_be_bytes()); // i is the iv

		let s = digest_size * i;
		let e = if (s + digest_size) > size {
			s + padding
		} else {
			s + digest_size
		};
		sha256.update(&src[s..e]);
		dst[s..e].copy_from_slice(&sha256.finalize_reset()[..]);
	}
}

/// Recovers information from data that was split with `cryptsetup`'s `afsplitter` implementation.
///
/// The blocksize and blocknumber values must be the same as when splitting the information. Only SHA-256 is supported.
pub fn merge(src: &[u8], blocksize: usize, blocknumbers: usize) -> Vec<u8> {
	let mut bufblock = vec![0; blocksize];

	for i in 0..blocknumbers {
		let s = blocksize * i;
		let e = s + blocksize;
		xor_block(&src[s..e], &bufblock.clone(), &mut bufblock, blocksize);
		if i < (blocknumbers - 1) {
			diffuse(&bufblock.clone(), &mut bufblock, blocksize);
		}
	}

	bufblock
}
