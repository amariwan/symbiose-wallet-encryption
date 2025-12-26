/// Tunable Argon2id parameters. Increase `memory_kib` to raise GPU cracking cost.
#[derive(Clone, Copy, Debug)]
pub struct Argon2Params {
    pub iterations: u32,
    pub memory_kib: u32,
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self {
            iterations: 15,
            memory_kib: 65_536, // 64 MiB baseline for desktop/server
        }
    }
}

/// Security parameters used by the public byte-oriented APIs.
/// Mirrors `Argon2Params` but provides a semantically clearer name.
#[derive(Clone, Copy, Debug)]
pub struct SecurityParams {
    pub iterations: u32,
    pub memory_kib: u32,
}

impl Default for SecurityParams {
    fn default() -> Self {
        Self {
            iterations: 15,
            memory_kib: 65_536, // 64 MiB baseline for desktop/server
        }
    }
}

impl From<SecurityParams> for Argon2Params {
    fn from(p: SecurityParams) -> Self {
        Self {
            iterations: p.iterations,
            memory_kib: p.memory_kib,
        }
    }
}

impl From<Argon2Params> for SecurityParams {
    fn from(p: Argon2Params) -> Self {
        Self {
            iterations: p.iterations,
            memory_kib: p.memory_kib,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conversions_preserve_values() {
        let argon = Argon2Params {
            iterations: 3,
            memory_kib: 2048,
        };

        let security: SecurityParams = argon.into();
        assert_eq!(security.iterations, 3);
        assert_eq!(security.memory_kib, 2048);

        let roundtrip: Argon2Params = security.into();
        assert_eq!(roundtrip.iterations, argon.iterations);
        assert_eq!(roundtrip.memory_kib, argon.memory_kib);
    }
}
