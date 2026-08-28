use std::{fs, io::Read, path::Path};

use quick_xml::{events::Event, Reader};
use zip::ZipArchive;

use crate::ScanError;

/// 返回可扫描文本；PDF 和未知格式明确不尝试提取。
pub fn extract_text(path: &Path) -> Result<Option<String>, ScanError> {
    match extension(path).as_deref() {
        Some("txt" | "csv") => Ok(Some(String::from_utf8_lossy(&fs::read(path)?).into_owned())),
        Some("docx" | "xlsx" | "pptx") => extract_office_xml(path).map(Some),
        Some("pdf") | None | Some(_) => Ok(None),
    }
}

fn extension(path: &Path) -> Option<String> {
    path.extension()
        .and_then(|extension| extension.to_str())
        .map(str::to_ascii_lowercase)
}

fn extract_office_xml(path: &Path) -> Result<String, ScanError> {
    let file = fs::File::open(path)?;
    let mut archive =
        ZipArchive::new(file).map_err(|error| ScanError::Office(error.to_string()))?;
    let mut text = String::new();

    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .map_err(|error| ScanError::Office(error.to_string()))?;
        if !entry.name().ends_with(".xml") {
            continue;
        }
        let mut xml = String::new();
        entry.read_to_string(&mut xml)?;
        text.push_str(&xml_text(&xml)?);
        text.push('\n');
    }
    Ok(text)
}

fn xml_text(xml: &str) -> Result<String, ScanError> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(false);
    let mut text = String::new();
    let mut buffer = Vec::new();

    loop {
        match reader.read_event_into(&mut buffer) {
            Ok(Event::Text(value)) => text.push_str(
                value
                    .unescape()
                    .map_err(|error| ScanError::Office(error.to_string()))?
                    .as_ref(),
            ),
            Ok(Event::CData(value)) => text.push_str(&String::from_utf8_lossy(value.as_ref())),
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(error) => return Err(ScanError::Office(error.to_string())),
        }
        buffer.clear();
    }
    Ok(text)
}
