use zeroize::Zeroize;

/// Wrapper for sensitive data that will be automatically zeroed when dropped
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct SensitiveData(pub Vec<u8>);

impl SensitiveData {
    /// Creates a new SensitiveData wrapper from a vector
    pub fn new(data: Vec<u8>) -> Self {
        Self(data)
    }

    /// Returns a reference to the inner data
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exposes_inner_bytes() {
        let data = vec![1u8, 2, 3];
        let sensitive = SensitiveData::new(data.clone());

        assert_eq!(sensitive.as_bytes(), data.as_slice());
    }

    #[test]
    fn zeroize_trait_clears_buffer() {
        let mut sensitive = SensitiveData::new(vec![0xAAu8; 4]);
        sensitive.0.zeroize();

        assert!(sensitive.0.iter().all(|&b| b == 0));
    }
}
