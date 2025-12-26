use orion::hazardous::mac::poly1305::POLY1305_OUTSIZE;

// Constants for data layout
pub const SALT_LEN: usize = 32;
pub const NONCE_LEN: usize = 24; // XChaCha20-Poly1305 nonce size
pub const TAG_LEN: usize = POLY1305_OUTSIZE; // 16 bytes

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn constants_match_expected_sizes() {
		assert_eq!(SALT_LEN, 32);
		assert_eq!(NONCE_LEN, 24);
		assert_eq!(TAG_LEN, 16);
	}
}
