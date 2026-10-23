//! 登录页策略导入磁贴图标。
//!
//! 位图由 `docs/design/anchor-guard-import-tile-opaque.svg` 生成，直接嵌入 DLL，
//! 登录界面不依赖外部图片文件或图片解码库。

use std::{mem::size_of, ptr::null_mut};

use windows::{
    core::{Error, Result},
    Win32::{
        Foundation::E_INVALIDARG,
        Graphics::Gdi::{
            CreateDIBSection, BITMAPINFO, BITMAPINFOHEADER, BI_RGB, DIB_RGB_COLORS, HBITMAP,
        },
    },
};

const ICON_BMP: &[u8] = include_bytes!("../assets/anchor-guard-import-tile.bmp");

/// 从嵌入的 BMP 创建登录页磁贴位图。调用方负责释放返回的 `HBITMAP`。
pub fn tile_bitmap() -> Result<HBITMAP> {
    let offset = read_u32(10).ok_or_else(invalid_bitmap)? as usize;
    let width = read_i32(18).ok_or_else(invalid_bitmap)?;
    let height = read_i32(22).ok_or_else(invalid_bitmap)?;
    let bits_per_pixel = read_u16(28).ok_or_else(invalid_bitmap)?;
    let compression = read_u32(30).ok_or_else(invalid_bitmap)?;
    if width <= 0
        || height == 0
        || (bits_per_pixel != 24 && bits_per_pixel != 32)
        || compression != BI_RGB.0
    {
        return Err(invalid_bitmap());
    }

    let rows = height.unsigned_abs() as usize;
    let row_bytes = (width as usize * (bits_per_pixel as usize / 8) + 3) & !3;
    let pixel_bytes = row_bytes.checked_mul(rows).ok_or_else(invalid_bitmap)?;
    let pixels = ICON_BMP
        .get(offset..offset + pixel_bytes)
        .ok_or_else(invalid_bitmap)?;

    let info = BITMAPINFO {
        bmiHeader: BITMAPINFOHEADER {
            biSize: size_of::<BITMAPINFOHEADER>() as u32,
            biWidth: width,
            biHeight: height,
            biPlanes: 1,
            biBitCount: bits_per_pixel,
            biCompression: BI_RGB.0,
            biSizeImage: pixel_bytes as u32,
            ..Default::default()
        },
        ..Default::default()
    };
    let mut bits = null_mut();
    let bitmap = unsafe { CreateDIBSection(None, &info, DIB_RGB_COLORS, &mut bits, None, 0) }?;
    if bits.is_null() {
        return Err(invalid_bitmap());
    }

    // BMP 与 DIB 使用相同的行序约定：高度为负时都是自上而下，为正时都是自下而上。
    unsafe { std::ptr::copy_nonoverlapping(pixels.as_ptr(), bits.cast::<u8>(), pixel_bytes) };
    Ok(bitmap)
}

fn invalid_bitmap() -> Error {
    Error::from(E_INVALIDARG)
}

fn read_u16(offset: usize) -> Option<u16> {
    ICON_BMP
        .get(offset..offset + 2)?
        .try_into()
        .ok()
        .map(u16::from_le_bytes)
}

fn read_u32(offset: usize) -> Option<u32> {
    ICON_BMP
        .get(offset..offset + 4)?
        .try_into()
        .ok()
        .map(u32::from_le_bytes)
}

fn read_i32(offset: usize) -> Option<i32> {
    ICON_BMP
        .get(offset..offset + 4)?
        .try_into()
        .ok()
        .map(i32::from_le_bytes)
}

#[cfg(test)]
mod tests {
    use super::tile_bitmap;

    #[test]
    fn embedded_tile_bitmap_is_created() {
        let bitmap = tile_bitmap().unwrap();

        assert!(!bitmap.0.is_null());
    }
}
