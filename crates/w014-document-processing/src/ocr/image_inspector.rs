//! Image header dimension inspection and raster limit enforcement (WI-0207).
//!
//! Enforces:
//! - Raster limit: <= 40 Megapixels (40,000,000 pixels) per page/image
//! - Pure Rust inspection of PNG, JPEG, GIF, BMP, TIFF, and WebP headers
//! - Fail closed on invalid dimensions, integer overflow, or exceeded bounds

use super::config::MAX_RASTER_PIXELS;
use super::error::OcrError;

/// Image dimension inspection result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImageDimensions {
    pub width: u32,
    pub height: u32,
    pub total_pixels: u64,
}

/// Inspects image bytes to extract dimensions and verify the <= 40 MP raster ceiling.
///
/// # Errors
/// Fails closed if the image header is unrecognized, corrupted, or exceeds 40 MP.
pub fn inspect_and_validate_raster(image_bytes: &[u8]) -> Result<ImageDimensions, OcrError> {
    if image_bytes.is_empty() {
        return Err(OcrError::ExecutionFailed {
            code: "EMPTY_IMAGE_BYTES".to_string(),
            detail: "Image byte buffer is empty".to_string(),
        });
    }

    let dims = parse_image_dimensions(image_bytes).ok_or_else(|| OcrError::ExecutionFailed {
        code: "INVALID_IMAGE_HEADER".to_string(),
        detail: "Unable to parse image dimensions from header".to_string(),
    })?;

    let total_pixels =
        (dims.width as u64)
            .checked_mul(dims.height as u64)
            .ok_or(OcrError::RasterExceeded {
                pixels: u64::MAX,
                limit: MAX_RASTER_PIXELS,
            })?;

    if total_pixels > MAX_RASTER_PIXELS {
        return Err(OcrError::RasterExceeded {
            pixels: total_pixels,
            limit: MAX_RASTER_PIXELS,
        });
    }

    Ok(ImageDimensions {
        width: dims.width,
        height: dims.height,
        total_pixels,
    })
}

/// Helper struct for parsed width and height.
struct RawDimensions {
    width: u32,
    height: u32,
}

fn parse_image_dimensions(bytes: &[u8]) -> Option<RawDimensions> {
    // 1. PNG check: starts with \x89PNG\r\n\x1a\n (8 bytes), IHDR at byte 12 (width at 16..20, height at 20..24)
    if bytes.len() >= 24 && bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        let width = u32::from_be_bytes(bytes[16..20].try_into().ok()?);
        let height = u32::from_be_bytes(bytes[20..24].try_into().ok()?);
        return Some(RawDimensions { width, height });
    }

    // 2. JPEG check: starts with 0xFF 0xD8 (SOI)
    if bytes.len() >= 4 && bytes[0] == 0xFF && bytes[1] == 0xD8 {
        let mut idx = 2;
        while idx + 4 < bytes.len() {
            if bytes[idx] != 0xFF {
                idx += 1;
                continue;
            }
            let marker = bytes[idx + 1];
            // SOF0 (0xC0), SOF1 (0xC1), SOF2 (0xC2) markers contain dimensions
            if matches!(
                marker,
                0xC0 | 0xC1
                    | 0xC2
                    | 0xC3
                    | 0xC5
                    | 0xC6
                    | 0xC7
                    | 0xC9
                    | 0xCA
                    | 0xCB
                    | 0xCD
                    | 0xCE
                    | 0xCF
            ) {
                if idx + 9 <= bytes.len() {
                    let height =
                        u16::from_be_bytes(bytes[idx + 5..idx + 7].try_into().ok()?) as u32;
                    let width = u16::from_be_bytes(bytes[idx + 7..idx + 9].try_into().ok()?) as u32;
                    return Some(RawDimensions { width, height });
                }
                break;
            }
            // Skip other segments
            let length = u16::from_be_bytes(bytes[idx + 2..idx + 4].try_into().ok()?) as usize;
            idx += 2 + length;
        }
    }

    // 3. GIF check: starts with "GIF87a" or "GIF89a", width at 6..8, height at 8..10 (little endian)
    if bytes.len() >= 10 && (bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a")) {
        let width = u16::from_le_bytes(bytes[6..8].try_into().ok()?) as u32;
        let height = u16::from_le_bytes(bytes[8..10].try_into().ok()?) as u32;
        return Some(RawDimensions { width, height });
    }

    // 4. BMP check: starts with "BM", width at 18..22, height at 22..26 (little endian)
    if bytes.len() >= 26 && bytes.starts_with(b"BM") {
        let width = u32::from_le_bytes(bytes[18..22].try_into().ok()?);
        let height = i32::from_le_bytes(bytes[22..26].try_into().ok()?).unsigned_abs();
        return Some(RawDimensions { width, height });
    }

    // 5. TIFF check: starts with "II\x2A\x00" (little endian) or "MM\x00\x2A" (big endian)
    if bytes.len() >= 8 && (bytes.starts_with(b"II\x2A\x00") || bytes.starts_with(b"MM\x00\x2A")) {
        let is_le = bytes[0] == b'I';
        let ifd_offset = if is_le {
            u32::from_le_bytes(bytes[4..8].try_into().ok()?) as usize
        } else {
            u32::from_be_bytes(bytes[4..8].try_into().ok()?) as usize
        };

        if ifd_offset + 2 <= bytes.len() {
            let num_entries = if is_le {
                u16::from_le_bytes(bytes[ifd_offset..ifd_offset + 2].try_into().ok()?) as usize
            } else {
                u16::from_be_bytes(bytes[ifd_offset..ifd_offset + 2].try_into().ok()?) as usize
            };

            let mut width = None;
            let mut height = None;

            for e in 0..num_entries {
                let entry_offset = ifd_offset + 2 + e * 12;
                if entry_offset + 12 > bytes.len() {
                    break;
                }
                let tag = if is_le {
                    u16::from_le_bytes(bytes[entry_offset..entry_offset + 2].try_into().ok()?)
                } else {
                    u16::from_be_bytes(bytes[entry_offset..entry_offset + 2].try_into().ok()?)
                };
                let val_bytes = &bytes[entry_offset + 8..entry_offset + 12];
                let val = if is_le {
                    u32::from_le_bytes(val_bytes.try_into().ok()?)
                } else {
                    u32::from_be_bytes(val_bytes.try_into().ok()?)
                };

                if tag == 256 {
                    width = Some(val);
                } else if tag == 257 {
                    height = Some(val);
                }
            }

            if let (Some(w), Some(h)) = (width, height) {
                return Some(RawDimensions {
                    width: w,
                    height: h,
                });
            }
        }
    }

    // 6. WebP check: starts with "RIFF" and "WEBP"
    if bytes.len() >= 30 && bytes.starts_with(b"RIFF") && &bytes[8..12] == b"WEBP" {
        // VP8 (lossy) check
        if &bytes[12..16] == b"VP8 " && bytes.len() >= 30 {
            let width = (u16::from_le_bytes(bytes[26..28].try_into().ok()?) & 0x3FFF) as u32;
            let height = (u16::from_le_bytes(bytes[28..30].try_into().ok()?) & 0x3FFF) as u32;
            return Some(RawDimensions { width, height });
        }
        // VP8L (lossless) check
        if &bytes[12..16] == b"VP8L" && bytes.len() >= 25 {
            let b0 = bytes[21] as u32;
            let b1 = bytes[22] as u32;
            let b2 = bytes[23] as u32;
            let b3 = bytes[24] as u32;
            let width = 1 + (b0 | ((b1 & 0x3F) << 8));
            let height = 1 + ((b1 >> 6) | (b2 << 2) | ((b3 & 0x0F) << 10));
            return Some(RawDimensions { width, height });
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_png_dimensions() {
        let mut png = Vec::new();
        png.extend_from_slice(b"\x89PNG\r\n\x1a\n"); // 8 bytes signature
        png.extend_from_slice(&[0, 0, 0, 13]); // chunk length 13
        png.extend_from_slice(b"IHDR"); // chunk type
        png.extend_from_slice(&800u32.to_be_bytes()); // width 800
        png.extend_from_slice(&600u32.to_be_bytes()); // height 600
        png.extend_from_slice(&[8, 2, 0, 0, 0]); // bit depth, color type, compression, filter, interlace

        let res = inspect_and_validate_raster(&png).expect("PNG validation should succeed");
        assert_eq!(res.width, 800);
        assert_eq!(res.height, 600);
        assert_eq!(res.total_pixels, 480_000);
    }

    #[test]
    fn test_png_exceeds_40mp_rejected() {
        let mut png = Vec::new();
        png.extend_from_slice(b"\x89PNG\r\n\x1a\n");
        png.extend_from_slice(&[0, 0, 0, 13]);
        png.extend_from_slice(b"IHDR");
        png.extend_from_slice(&10_000u32.to_be_bytes()); // width 10,000
        png.extend_from_slice(&5_000u32.to_be_bytes()); // height 5,000 -> 50 MP > 40 MP
        png.extend_from_slice(&[8, 2, 0, 0, 0]);

        let res = inspect_and_validate_raster(&png);
        assert!(matches!(res, Err(OcrError::RasterExceeded { .. })));
    }
}
