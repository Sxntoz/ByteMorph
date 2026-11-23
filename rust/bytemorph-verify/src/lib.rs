//! Safe binary pre-validation and entropy diagnostics for ByteMorph.
//! Treats all input slices as untrusted and avoids unsafe code.

#![forbid(unsafe_code)]

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectedFormat {
    Unknown,
    Pe32,
    Pe32Plus,
    Elf32,
    Elf64,
    MachO32,
    MachO64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    EmptyInput,
    TruncatedHeader,
    InvalidMagic,
    OutOfBoundsOffset,
}

/// Validates basic container headers without panicking on truncated or malformed inputs.
pub fn validate_header(data: &[u8]) -> Result<DetectedFormat, VerifyError> {
    if data.is_empty() {
        return Err(VerifyError::EmptyInput);
    }
    if data.len() < 4 {
        return Err(VerifyError::TruncatedHeader);
    }

    // ELF
    if data[0..4] == [0x7F, b'E', b'L', b'F'] {
        if data.len() < 20 {
            return Err(VerifyError::TruncatedHeader);
        }
        return match data[4] {
            1 => Ok(DetectedFormat::Elf32),
            2 => Ok(DetectedFormat::Elf64),
            _ => Err(VerifyError::InvalidMagic),
        };
    }

    // PE
    if data[0..2] == [b'M', b'Z'] {
        if data.len() < 0x40 {
            return Err(VerifyError::TruncatedHeader);
        }
        let lfanew = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
        let end = lfanew.checked_add(26).ok_or(VerifyError::OutOfBoundsOffset)?;
        if end > data.len() {
            return Err(VerifyError::OutOfBoundsOffset);
        }
        if &data[lfanew..lfanew + 4] != b"PE\0\0" {
            return Err(VerifyError::InvalidMagic);
        }
        let opt_magic = u16::from_le_bytes([data[lfanew + 24], data[lfanew + 25]]);
        return match opt_magic {
            0x10B => Ok(DetectedFormat::Pe32),
            0x20B => Ok(DetectedFormat::Pe32Plus),
            _ => Err(VerifyError::InvalidMagic),
        };
    }

    // Mach-O
    let magic_be = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    let magic_le = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    if magic_be == 0xFEED_FACE || magic_le == 0xFEED_FACE {
        return Ok(DetectedFormat::MachO32);
    }
    if magic_be == 0xFEED_FACF || magic_le == 0xFEED_FACF {
        return Ok(DetectedFormat::MachO64);
    }

    Err(VerifyError::InvalidMagic)
}

/// Computes Shannon entropy in bits per byte [0.0, 8.0] for section/buffer diagnostics.
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut entropy = 0.0;
    for &c in &counts {
        if c > 0 {
            let p = (c as f64) / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_and_truncated() {
        assert_eq!(validate_header(&[]), Err(VerifyError::EmptyInput));
        assert_eq!(validate_header(&[0x7F, b'E']), Err(VerifyError::TruncatedHeader));
        assert_eq!(validate_header(&[0x7F, b'E', b'L', b'F', 2]), Err(VerifyError::TruncatedHeader));
    }

    #[test]
    fn detects_elf64_and_pe32_plus() {
        let mut elf = vec![0u8; 64];
        elf[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
        elf[4] = 2;
        assert_eq!(validate_header(&elf), Ok(DetectedFormat::Elf64));

        let mut pe = vec![0u8; 0xB0];
        pe[0] = b'M';
        pe[1] = b'Z';
        pe[0x3C] = 0x80;
        pe[0x80..0x84].copy_from_slice(b"PE\0\0");
        pe[0x98] = 0x0B;
        pe[0x99] = 0x02;
        assert_eq!(validate_header(&pe), Ok(DetectedFormat::Pe32Plus));
    }

    #[test]
    fn entropy_bounds() {
        assert_eq!(shannon_entropy(&[]), 0.0);
        assert_eq!(shannon_entropy(&[0xAA; 128]), 0.0);
        let uniform: Vec<u8> = (0..=255).collect();
        let e = shannon_entropy(&uniform);
        assert!((e - 8.0).abs() < 1e-9);
    }
}
