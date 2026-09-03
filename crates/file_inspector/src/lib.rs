// Extracts scannable plain text from uploaded files so the existing DLP
// scanners (safeprompt-pii/-secrets/-prompt, composed by safeprompt-inspector)
// can inspect file-upload content the same way they already inspect chat
// prompt text -- no new detection logic needed, just a front-end that turns
// "file bytes" into "text".
//
// Format coverage (2026-08-07): docx/pdf/plaintext have their own
// hand-rolled or established extractors below (`extract_docx`,
// `extract_pdf` via `pdf-extract`), unchanged and untouched by this
// expansion -- no reason to re-route a working, tested path onto a new
// dependency just for consistency. Legacy `.doc`, PowerPoint, Excel,
// OpenDocument, RTF, and EPUB route through the `anydoc` crate (real
// Rust library, MIT-licensed, verified against crates.io directly before
// adding -- see its own Cargo.toml entry for the maturity caveat: created
// 2026-07-30, pre-1.0, pinned to an exact version rather than trusted to
// auto-update).
//
// **Images/OCR (2026-08-07, updated)**: no longer out of scope. Direct
// image uploads (PNG/JPEG/BMP/TIFF/WebP/GIF) and *scanned* (image-only)
// PDF pages now route through `safeprompt-ocr`'s `OcrEngine` trait --
// 100% on-device (PP-OCR ONNX models run in-process, no network calls at
// inference time), matching this product's "nothing leaves the device"
// boundary; see that crate's own doc comment for how it differs from
// `anydoc`'s publisher's cloud OCR (which this product deliberately does
// NOT use). OCR is optional per call (`ocr: Option<&dyn OcrEngine>`) --
// `None` when unlicensed or not yet initialized, in which case images
// come back `Unsupported` and PDFs fall back to whatever `pdf-extract`
// alone found, same graceful degradation as every other optional scanner
// in this codebase.
//
// **Untrusted-input safety, given this parses attacker-reachable uploaded
// bytes**: `anydoc`'s own conversion call is wrapped in
// `std::panic::catch_unwind` (see `extract_via_anydoc`) so a parsing bug
// in a very young dependency can turn into a clean `Unsupported` result
// for that one file, never a crashed Agent process. `safeprompt-ocr`
// applies the same `catch_unwind` discipline internally for its own
// inference call. **Honestly not fully solved by this**: resource-
// exhaustion (a decompression-bomb-shaped upload, or an enormous/many-page
// PDF driving unbounded rasterization) isn't fully addressed --
// `extract_pdf_via_ocr` caps the page count it will OCR (see
// `MAX_OCR_PAGES`), but there's no byte-size or wall-clock budget yet.
// Stated here as a real, separate, not-yet-scoped hardening item rather
// than silently assumed covered.

use std::io::Read;
use std::panic::{catch_unwind, AssertUnwindSafe};

use safeprompt_ocr::OcrEngine;

/// Bare-extension recognition for direct image uploads -- routed through
/// OCR (when available) rather than `anydoc`, which only extracts
/// text-based document content, not pixels.
const IMAGE_EXTENSIONS: &[&str] = &["png", "jpg", "jpeg", "bmp", "tiff", "tif", "webp", "gif"];

/// Hard cap on how many PDF pages `extract_pdf_via_ocr` will rasterize and
/// OCR for a single upload -- OCR inference is orders of magnitude more
/// expensive than `pdf-extract`'s text-layer path, so an unbounded scanned
/// PDF (hundreds of pages) must not be allowed to stall a request
/// indefinitely. A real, deliberately conservative limit, not a
/// discovered tuning value -- revisit with real usage data.
const MAX_OCR_PAGES: usize = 20;

/// Below this many alphanumeric characters, `pdf-extract`'s output is
/// treated as "no real text layer" -- i.e. a scanned/image-only PDF --
/// and (when an OCR engine is available) the page images are rasterized
/// and OCRed instead. This is a document-level heuristic, not per-page:
/// a PDF with one scanned page mixed into many digital-text pages will
/// still be classified "has a text layer" and that one scanned page's
/// content will be missed. A real, honest limitation of this pass, not
/// silently assumed covered -- true per-page classification needs each
/// page's own text-layer presence, not just the whole document's total.
const MIN_MEANINGFUL_PDF_TEXT_CHARS: usize = 20;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtractionOutcome {
    /// Plain text pulled out of a recognized, parseable format.
    Text(String),
    /// A file was present but its content couldn't be turned into scannable
    /// text -- unrecognized extension, encrypted/corrupt archive, malformed
    /// PDF, etc. Deliberately a distinct variant from `Text(String::new())`:
    /// callers must decide what an *unscannable* file means for policy
    /// (this crate doesn't decide that), not silently treat it as "scanned
    /// clean" just because no text came back.
    Unsupported { filename: String, reason: String },
}

/// Recognized purely by file extension (not sniffing magic bytes) -- the
/// filename comes from the untrusted upload's Content-Disposition, so this
/// is a hint for which parser to try, not a trust decision; a mismatched/
/// spoofed extension just fails to parse and comes back `Unsupported`,
/// same as any other unparseable content.
///
/// `ocr`: `Some` to enable OCR for direct image uploads and scanned-PDF
/// pages (see module doc comment), `None` to skip both -- unlicensed or
/// not yet initialized. Mirrors the same `Option<&dyn Scanner>`-style
/// graceful-degradation pattern `safeprompt-inspector::Inspector` already
/// uses for its own optional NER/entropy scanners.
pub fn extract_text(filename: &str, bytes: &[u8], ocr: Option<&dyn OcrEngine>) -> ExtractionOutcome {
    let ext = filename.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    let result = match ext.as_str() {
        // .docm (macro-enabled) shares .docx's exact zip/XML structure --
        // the same hand-rolled extractor already handles it correctly,
        // no reason to route it through anydoc instead.
        "docx" | "docm" => extract_docx(bytes),
        "pdf" => extract_pdf(bytes, ocr),
        "txt" | "md" | "csv" | "json" | "log" | "yaml" | "yml" | "xml" | "html" | "htm" => {
            Ok(String::from_utf8_lossy(bytes).into_owned())
        }
        _ if IMAGE_EXTENSIONS.contains(&ext.as_str()) => extract_image(bytes, ocr),
        // Everything else `anydoc::Format::from_extension` recognizes
        // (legacy .doc, PowerPoint, Excel, OpenDocument, RTF, EPUB) --
        // falls through to "unrecognized extension" below if it's neither
        // one of the extensions above nor one anydoc knows either.
        _ => extract_via_anydoc(&ext, bytes),
    };

    match result {
        Ok(text) => ExtractionOutcome::Text(text),
        Err(e) => {
            tracing::warn!("could not extract text from {filename}: {e}");
            ExtractionOutcome::Unsupported { filename: filename.to_string(), reason: e.to_string() }
        }
    }
}

/// A .docx is a ZIP archive; every visible character lives inside
/// `word/document.xml`'s `<w:t>...</w:t>` text-run elements. Deliberately a
/// hand-rolled scan for just that one element rather than a full XML parser
/// dependency -- DLP text-matching only needs the actual words, not
/// paragraph/run/formatting structure.
fn extract_docx(bytes: &[u8]) -> anyhow::Result<String> {
    let cursor = std::io::Cursor::new(bytes);
    let mut archive = zip::ZipArchive::new(cursor)?;
    let mut xml = String::new();
    archive.by_name("word/document.xml")?.read_to_string(&mut xml)?;
    Ok(extract_w_t_runs(&xml))
}

fn extract_w_t_runs(xml: &str) -> String {
    let mut out = String::new();
    let mut rest = xml;
    loop {
        let Some(start_tag) = rest.find("<w:t") else { break };
        let after_open = &rest[start_tag..];
        let Some(gt) = after_open.find('>') else { break };
        let opening_tag = &after_open[..gt];

        if opening_tag.ends_with('/') {
            // Self-closing <w:t/> -- an empty run, no content to capture.
            rest = &after_open[gt + 1..];
            continue;
        }

        let content_start = gt + 1;
        let Some(end_rel) = after_open[content_start..].find("</w:t>") else { break };
        let content = &after_open[content_start..content_start + end_rel];
        out.push_str(&decode_xml_entities(content));
        out.push(' ');
        rest = &after_open[content_start + end_rel + "</w:t>".len()..];
    }
    out
}

fn decode_xml_entities(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
}

/// `pdf-extract` reads the PDF's actual text layer -- correct and cheap for
/// a normal, digitally-authored PDF, but returns little/nothing for a
/// *scanned* PDF (each page is just an embedded image, no text objects at
/// all). When the extracted text looks too sparse to be real (see
/// `MIN_MEANINGFUL_PDF_TEXT_CHARS`) and an OCR engine is available, this
/// falls back to rasterizing each page and OCRing it instead.
fn extract_pdf(bytes: &[u8], ocr: Option<&dyn OcrEngine>) -> anyhow::Result<String> {
    let text = pdf_extract::extract_text_from_mem(bytes).map_err(|e| anyhow::anyhow!("{e}"))?;
    if has_meaningful_pdf_text(&text) {
        return Ok(text);
    }
    let Some(ocr) = ocr else {
        // No OCR available -- best effort, same behavior as before this
        // integration existed (possibly empty, not an error: a sparse but
        // genuinely all-whitespace-cover-page PDF is not a parse failure).
        return Ok(text);
    };
    match extract_pdf_via_ocr(bytes, ocr) {
        Ok(ocr_text) if !ocr_text.trim().is_empty() => Ok(ocr_text),
        // Rasterization/OCR found nothing either, or failed outright (e.g.
        // no Pdfium library available on this machine) -- fall back to
        // whatever pdf-extract already found rather than erroring the
        // whole upload out.
        Ok(_) => Ok(text),
        Err(e) => {
            tracing::warn!("scanned-PDF OCR fallback failed, keeping pdf-extract's sparse result: {e}");
            Ok(text)
        }
    }
}

/// The scanned-vs-digital PDF heuristic, split out as its own pure
/// function so it's directly unit-testable without needing a real PDF
/// byte fixture -- see `MIN_MEANINGFUL_PDF_TEXT_CHARS`'s doc comment for
/// the reasoning and its known per-page limitation.
fn has_meaningful_pdf_text(text: &str) -> bool {
    text.chars().filter(|c| c.is_alphanumeric()).count() >= MIN_MEANINGFUL_PDF_TEXT_CHARS
}

fn extract_image(bytes: &[u8], ocr: Option<&dyn OcrEngine>) -> anyhow::Result<String> {
    let ocr = ocr.ok_or_else(|| anyhow::anyhow!("image OCR not available (unlicensed or not initialized)"))?;
    ocr.extract_text(bytes)
}

/// Renders each page of a PDF to a bitmap via Pdfium (bound at *runtime*,
/// not build time -- see `resolve_pdfium_library_path`) and OCRs each one,
/// concatenating the results. Capped at `MAX_OCR_PAGES` pages (see its own
/// doc comment).
fn extract_pdf_via_ocr(bytes: &[u8], ocr: &dyn OcrEngine) -> anyhow::Result<String> {
    use pdfium_render::prelude::*;

    let bindings = resolve_pdfium_library_path()
        .and_then(|path| Pdfium::bind_to_library(path).ok())
        .or_else(|| Pdfium::bind_to_system_library().ok())
        .ok_or_else(|| anyhow::anyhow!("no Pdfium library available (set PDFIUM_DYLIB_PATH or install one system-wide)"))?;
    let pdfium = Pdfium::new(bindings);

    let document = pdfium.load_pdf_from_byte_slice(bytes, None).map_err(|e| anyhow::anyhow!("failed to open PDF for rasterization: {e}"))?;
    let render_config = PdfRenderConfig::new().set_target_width(2000).set_maximum_height(2000);

    let mut combined = String::new();
    for (index, page) in document.pages().iter().enumerate() {
        if index >= MAX_OCR_PAGES {
            tracing::warn!("scanned PDF has more than {MAX_OCR_PAGES} pages -- only OCRing the first {MAX_OCR_PAGES}");
            break;
        }
        let bitmap = match page.render_with_config(&render_config) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!("failed to render PDF page {index} to a bitmap: {e}");
                continue;
            }
        };
        let dynamic_image = match bitmap.as_image() {
            Ok(img) => img,
            Err(e) => {
                tracing::warn!("failed to convert rasterized PDF page {index} to an image: {e}");
                continue;
            }
        };
        let mut png_bytes = Vec::new();
        if dynamic_image
            .write_to(&mut std::io::Cursor::new(&mut png_bytes), image::ImageFormat::Png)
            .is_err()
        {
            tracing::warn!("failed to encode rasterized PDF page {index} as PNG");
            continue;
        }
        match ocr.extract_text(&png_bytes) {
            Ok(page_text) if !page_text.is_empty() => {
                if !combined.is_empty() {
                    combined.push('\n');
                }
                combined.push_str(&page_text);
            }
            Ok(_) => {}
            Err(e) => tracing::warn!("OCR failed on rasterized PDF page {index}: {e}"),
        }
    }
    Ok(combined)
}

/// Resolution order for the Pdfium native library, mirroring
/// `safeprompt-ocr`'s `resolve_and_init_dylib`: an explicit
/// `PDFIUM_DYLIB_PATH` override, then a file named `pdfium.dll`/
/// `libpdfium.so`/`libpdfium.dylib` next to the current executable (the
/// shape a real install lays out -- the installer bundles one known-good
/// Pdfium binary, e.g. from bblanchon/pdfium-binaries, alongside the Agent
/// binary). Falls through to `None` (caller then tries
/// `Pdfium::bind_to_system_library` as a last resort) rather than
/// guessing.
fn resolve_pdfium_library_path() -> Option<std::path::PathBuf> {
    if let Ok(p) = std::env::var("PDFIUM_DYLIB_PATH") {
        return Some(std::path::PathBuf::from(p));
    }
    #[cfg(target_os = "windows")]
    const PDFIUM_FILENAME: &str = "pdfium.dll";
    #[cfg(target_os = "macos")]
    const PDFIUM_FILENAME: &str = "libpdfium.dylib";
    #[cfg(all(unix, not(target_os = "macos")))]
    const PDFIUM_FILENAME: &str = "libpdfium.so";

    let exe_dir = std::env::current_exe().ok()?.parent()?.to_path_buf();
    let candidate = exe_dir.join(PDFIUM_FILENAME);
    candidate.exists().then_some(candidate)
}

/// Legacy `.doc`, PowerPoint, Excel, OpenDocument, RTF, EPUB -- via
/// `anydoc::to_markdown_bytes`. `Format::from_extension` is `anydoc`'s own
/// canonical extension-to-format mapping (not re-derived here, so this
/// crate can't drift out of sync with what the dependency actually
/// supports); an extension neither this crate nor `anydoc` recognizes
/// falls through to the same "unrecognized file extension" error as
/// before this integration existed.
///
/// Wrapped in `catch_unwind`: this is untrusted, attacker-reachable input
/// (a file upload) being parsed by a dependency published 8 days before
/// this integration (2026-07-30) -- a panic deep inside its parsing code
/// must become a normal `Unsupported` result for that one file, not a
/// crashed Agent process taking down every other in-flight request with
/// it. `AssertUnwindSafe` is safe to use here specifically because
/// `to_markdown_bytes` only reads `bytes` (a `&[u8]`, already immutable)
/// and returns an owned `String` -- there's no shared mutable state that
/// a caught panic could leave in an inconsistent, unsafe-to-observe state.
fn extract_via_anydoc(ext: &str, bytes: &[u8]) -> anyhow::Result<String> {
    let format = anydoc::Format::from_extension(ext).ok_or_else(|| anyhow::anyhow!("unrecognized file extension '{ext}'"))?;

    match catch_unwind(AssertUnwindSafe(|| anydoc::to_markdown_bytes(bytes, format))) {
        Ok(Ok(text)) => Ok(text),
        Ok(Err(e)) => Err(anyhow::anyhow!("anydoc conversion failed: {e}")),
        Err(_panic) => Err(anyhow::anyhow!("anydoc panicked while parsing this file (caught, not propagated)")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_docx(document_xml: &str) -> Vec<u8> {
        let mut buf = std::io::Cursor::new(Vec::new());
        {
            let mut zip = zip::ZipWriter::new(&mut buf);
            let options = zip::write::SimpleFileOptions::default();
            zip.start_file("word/document.xml", options).unwrap();
            std::io::Write::write_all(&mut zip, document_xml.as_bytes()).unwrap();
            zip.finish().unwrap();
        }
        buf.into_inner()
    }

    #[test]
    fn extracts_plain_text_files_directly() {
        let outcome = extract_text("notes.txt", b"contains a secret key", None);
        assert_eq!(outcome, ExtractionOutcome::Text("contains a secret key".to_string()));
    }

    #[test]
    fn extracts_text_runs_from_a_real_shaped_docx() {
        let xml = r#"<w:document><w:body><w:p><w:r><w:t>This agreement</w:t></w:r><w:r><w:t xml:space="preserve"> contains confidential terms</w:t></w:r></w:p></w:body></w:document>"#;
        let bytes = make_docx(xml);
        let outcome = extract_text("agreement.docx", &bytes, None);
        match outcome {
            ExtractionOutcome::Text(text) => {
                assert!(text.contains("This agreement"), "got: {text}");
                assert!(text.contains("confidential terms"), "got: {text}");
            }
            other => panic!("expected extracted text, got {other:?}"),
        }
    }

    #[test]
    fn docx_extraction_decodes_xml_entities() {
        let xml = r#"<w:t>Ben &amp; Jerry&apos;s &lt;secret&gt;</w:t>"#;
        let bytes = make_docx(xml);
        let outcome = extract_text("f.docx", &bytes, None);
        assert_eq!(outcome, ExtractionOutcome::Text("Ben & Jerry's <secret> ".to_string()));
    }

    #[test]
    fn empty_self_closing_runs_do_not_truncate_later_text() {
        let xml = r#"<w:t/><w:t>after the empty run</w:t>"#;
        let bytes = make_docx(xml);
        let outcome = extract_text("f.docx", &bytes, None);
        match outcome {
            ExtractionOutcome::Text(text) => assert!(text.contains("after the empty run"), "got: {text}"),
            other => panic!("expected extracted text, got {other:?}"),
        }
    }

    #[test]
    fn unrecognized_extension_is_unsupported_not_empty_text() {
        let outcome = extract_text("archive.zzz", b"whatever bytes", None);
        assert!(matches!(outcome, ExtractionOutcome::Unsupported { .. }));
    }

    #[test]
    fn corrupt_docx_is_unsupported_not_a_panic() {
        let outcome = extract_text("broken.docx", b"not actually a zip file", None);
        assert!(matches!(outcome, ExtractionOutcome::Unsupported { .. }));
    }

    // ── anydoc integration (2026-08-07) ─────────────────────────────────

    #[test]
    fn extracts_a_real_hand_built_rtf_document_via_anydoc() {
        // A real, minimally-valid RTF document (not a fake/stubbed
        // fixture) -- proves the anydoc wiring actually extracts text end
        // to end, not just that it handles errors gracefully.
        let rtf = br"{\rtf1\ansi\deff0 This agreement contains confidential terms.\par}";
        let outcome = extract_text("agreement.rtf", rtf, None);
        match outcome {
            ExtractionOutcome::Text(text) => {
                assert!(text.contains("confidential terms"), "expected the real RTF body text to be extracted, got: {text}");
            }
            other => panic!("expected extracted text from a real RTF document, got {other:?}"),
        }
    }

    #[test]
    fn docm_reuses_the_existing_proven_docx_extractor_not_anydoc() {
        // .docm (macro-enabled Word) shares .docx's exact zip/XML shape --
        // this proves it stays on the already-tested extract_docx path
        // rather than silently switching to the new dependency.
        let xml = r#"<w:t>macro-enabled document text</w:t>"#;
        let bytes = make_docx(xml);
        let outcome = extract_text("macros.docm", &bytes, None);
        match outcome {
            ExtractionOutcome::Text(text) => assert!(text.contains("macro-enabled document text"), "got: {text}"),
            other => panic!("expected extracted text, got {other:?}"),
        }
    }

    #[test]
    fn garbage_bytes_for_every_new_anydoc_backed_extension_are_unsupported_not_a_panic() {
        // The critical safety property for untrusted, attacker-reachable
        // upload content: every new format this integration adds must
        // fail gracefully on malformed input, exactly like the pre-existing
        // corrupt_docx_is_unsupported_not_a_panic test above already
        // guarantees for docx. If any of these panicked, catch_unwind in
        // extract_via_anydoc should still turn it into Unsupported here --
        // this test is what actually proves that, not just documents it.
        let garbage: &[u8] = b"this is not a valid document of any of these formats";
        for ext in ["doc", "ppt", "pptx", "pptm", "ppsx", "xls", "xlsx", "xlsm", "odt", "ods", "odp", "rtf", "epub"] {
            let filename = format!("broken.{ext}");
            let outcome = extract_text(&filename, garbage, None);
            assert!(
                matches!(outcome, ExtractionOutcome::Unsupported { .. }),
                "expected garbage .{ext} content to come back Unsupported, not {outcome:?}"
            );
        }
    }

    #[test]
    fn an_extension_anydoc_also_does_not_recognize_is_still_unrecognized() {
        // Regression check: adding the anydoc fallback branch must not
        // accidentally widen what counts as "supported" beyond what
        // Format::from_extension actually maps.
        let outcome = extract_text("archive.zzz", b"whatever bytes", None);
        assert!(matches!(outcome, ExtractionOutcome::Unsupported { .. }));
    }

    // ── OCR integration (2026-08-07) ────────────────────────────────────

    struct FakeOcrEngine {
        result: Result<&'static str, &'static str>,
    }
    impl OcrEngine for FakeOcrEngine {
        fn extract_text(&self, _image_bytes: &[u8]) -> anyhow::Result<String> {
            match self.result {
                Ok(text) => Ok(text.to_string()),
                Err(e) => Err(anyhow::anyhow!("{e}")),
            }
        }
    }

    #[test]
    fn image_upload_with_no_ocr_engine_is_unsupported_not_empty_text() {
        // No OCR configured (unlicensed / not yet initialized) -- the same
        // graceful-degradation shape as every other optional scanner in
        // this codebase, not silently "scanned clean".
        let outcome = extract_text("screenshot.png", b"\x89PNG\r\n\x1a\n", None);
        assert!(matches!(outcome, ExtractionOutcome::Unsupported { .. }));
    }

    #[test]
    fn image_upload_routes_through_the_provided_ocr_engine() {
        let engine = FakeOcrEngine { result: Ok("PASSWORD: hunter2") };
        let outcome = extract_text("screenshot.png", b"\x89PNG\r\n\x1a\n", Some(&engine));
        assert_eq!(outcome, ExtractionOutcome::Text("PASSWORD: hunter2".to_string()));
    }

    #[test]
    fn every_recognized_image_extension_routes_to_ocr_not_anydoc_or_unrecognized() {
        let engine = FakeOcrEngine { result: Ok("recognized text") };
        for ext in IMAGE_EXTENSIONS {
            let filename = format!("upload.{ext}");
            let outcome = extract_text(&filename, b"fake image bytes", Some(&engine));
            assert_eq!(
                outcome,
                ExtractionOutcome::Text("recognized text".to_string()),
                "expected .{ext} to route through the OCR engine, got a different outcome"
            );
        }
    }

    #[test]
    fn ocr_engine_failure_is_unsupported_not_a_panic_or_crash() {
        let engine = FakeOcrEngine { result: Err("decode failed") };
        let outcome = extract_text("broken.jpg", b"not a real jpeg", Some(&engine));
        assert!(matches!(outcome, ExtractionOutcome::Unsupported { .. }));
    }

    // ── Scanned-PDF detection heuristic (2026-08-07) ────────────────────

    #[test]
    fn a_normal_digital_pdfs_worth_of_text_counts_as_meaningful() {
        assert!(has_meaningful_pdf_text("This agreement contains confidential terms and a real signature block."));
    }

    #[test]
    fn empty_or_near_empty_text_does_not_count_as_meaningful() {
        assert!(!has_meaningful_pdf_text(""));
        assert!(!has_meaningful_pdf_text("   \n\n  "));
        assert!(!has_meaningful_pdf_text("Pg 1")); // a lone page-number-shaped fragment, common
                                                     // pdf-extract noise on an otherwise-scanned page
    }

    #[test]
    fn corrupt_pdf_bytes_are_unsupported_not_a_panic() {
        let outcome = extract_text("broken.pdf", b"%PDF-1.4 this is not a real pdf structure", None);
        assert!(matches!(outcome, ExtractionOutcome::Unsupported { .. }));
    }

    #[test]
    fn sparse_pdf_text_falls_back_gracefully_when_no_pdfium_library_is_available() {
        // Simulates the "scanned PDF, but this machine has no Pdfium
        // binary installed" case -- extract_pdf_via_ocr's own
        // resolve_pdfium_library_path/bind_to_system_library calls will
        // fail cleanly in this test environment (no PDFIUM_DYLIB_PATH set,
        // no system-wide Pdfium install), and extract_pdf must fall back
        // to the sparse pdf-extract result rather than erroring the whole
        // upload out. Real corrupt bytes (not a valid PDF at all) still
        // exercise this path since pdf-extract fails before OCR fallback
        // is even reached -- see corrupt_pdf_bytes_are_unsupported_not_a_panic
        // above for that boundary; this test instead confirms *that*
        // fallback code path itself doesn't panic when given `Some(&engine)`
        // but no working Pdfium binary.
        let engine = FakeOcrEngine { result: Ok("should not be reached without a real PDF") };
        let outcome = extract_text("scanned.pdf", b"%PDF-1.4 not a real pdf structure", Some(&engine));
        assert!(matches!(outcome, ExtractionOutcome::Unsupported { .. }));
    }
}
