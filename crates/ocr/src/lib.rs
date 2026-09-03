//! Local, on-device OCR (2026-08-07) -- screenshots, images, and scanned PDF
//! pages become another text source for the existing DLP scanners
//! (safeprompt-pii/-secrets/-prompt via safeprompt-inspector), matching this
//! product's "nothing leaves the device" boundary: no bytes, no image, no
//! extracted text are ever sent anywhere for this to work.
//!
//! Wraps `oar-ocr` (PP-OCR ONNX models run in-process via the `ort` ONNX
//! Runtime bindings -- no network calls at inference time) behind a small
//! [`OcrEngine`] trait so the backend can be swapped later (a different
//! engine, a platform-native API) without touching callers in
//! `safeprompt-file-inspector` or `safeprompt-inspector`.
//!
//! **Model provisioning** (verified 2026-08-07, not assumed): the
//! `auto-download` Cargo feature lets `OAROCRBuilder::new` accept *bare*
//! model names -- no directory component -- which it resolves against its
//! own bundled registry, checking (1) an existing local file of that name,
//! then (2) a cached copy under `$OAR_HOME` (`~/.oar` by default,
//! overridable via the `OAR_HOME` env var), then (3) downloading it and
//! verifying its SHA-256. That download only happens once per machine, the
//! first time OCR actually runs -- this crate ships no model bytes itself.
//! The three names used below (`pp-ocrv5_mobile_det.onnx`,
//! `en_pp-ocrv5_mobile_rec.onnx`, `ppocrv5_en_dict.txt`) are `oar-ocr`'s own
//! registered names for the PP-OCRv5 "mobile" (small, CPU-friendly)
//! detection model, English recognition model, and English character
//! dictionary respectively.
//!
//! **Scope of this pass**: English-only recognition model. Multi-language
//! support (Hindi/Tamil/Telugu/Kannada/Malayalam etc. for the India market)
//! is real future work -- `oar-ocr` supports swapping the recognition
//! model/dictionary pair for other PP-OCRv5 language packs, so extending
//! [`OarOcrEngine`] with a language parameter later is additive, not a
//! rewrite -- but it is NOT built here. Likewise: no SHA256 result caching,
//! no clipboard/screenshot capture, no per-tenant policy -- those stay
//! explicitly out of scope for this slice, tracked as open backlog rather
//! than silently assumed done.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Once;

use oar_ocr::prelude::*;

static DYLIB_INIT: Once = Once::new();

/// Platform-specific filename for the ONNX Runtime shared library this
/// crate loads at runtime (see the module doc comment's "load-dynamic"
/// explanation).
#[cfg(target_os = "windows")]
const ORT_DYLIB_FILENAME: &str = "onnxruntime.dll";
#[cfg(target_os = "macos")]
const ORT_DYLIB_FILENAME: &str = "libonnxruntime.dylib";
#[cfg(all(unix, not(target_os = "macos")))]
const ORT_DYLIB_FILENAME: &str = "libonnxruntime.so";

/// Resolves and loads the real ONNX Runtime shared library exactly once
/// per process. Resolution order: (1) `ORT_DYLIB_PATH` env var, an
/// explicit operator/installer override; (2) a file named
/// `onnxruntime.dll`/`.so`/`.dylib` next to the current executable -- the
/// shape a real install lays out (the installer bundles one known-good
/// ONNX Runtime binary alongside the Agent binary, see this crate's
/// Cargo.toml comment for why "load-dynamic" was chosen over statically
/// linking a build-time-downloaded copy). If neither exists, `ort` is left
/// to fall back to its own default search behavior, and any resulting
/// failure surfaces as a normal `Err` from `OAROCRBuilder::build` rather
/// than a panic.
fn resolve_and_init_dylib() {
    DYLIB_INIT.call_once(|| {
        let path = std::env::var("ORT_DYLIB_PATH").ok().map(std::path::PathBuf::from).or_else(|| {
            let exe_dir = std::env::current_exe().ok()?.parent()?.to_path_buf();
            let candidate = exe_dir.join(ORT_DYLIB_FILENAME);
            candidate.exists().then_some(candidate)
        });
        let Some(path) = path else {
            tracing::debug!(
                "no ORT_DYLIB_PATH set and no {ORT_DYLIB_FILENAME} found next to the executable -- \
                 leaving ONNX Runtime resolution to ort's own default search"
            );
            return;
        };
        match ort::init_from(path.to_string_lossy().into_owned()) {
            Ok(builder) => {
                // `commit()` returns `bool`: true if this call actually
                // became the process-wide ONNX Runtime environment (it can
                // only happen once); false just means something else beat
                // us to it, not a failure -- `DYLIB_INIT` already prevents
                // that within this crate, but `ort::init_from` itself is a
                // process-global choice another crate in the same binary
                // could also make.
                let became_active = builder.commit();
                tracing::info!("loaded ONNX Runtime from {} (became active: {became_active})", path.display());
            }
            Err(e) => tracing::warn!("failed to load ONNX Runtime from {}: {e}", path.display()),
        }
    });
}

/// The `oar-ocr` registry names for the model trio this crate uses --
/// English-only PP-OCRv5 "mobile" models, chosen for CPU-only inference
/// without a GPU dependency. See this module's doc comment for how these
/// names get resolved to actual files.
const DET_MODEL: &str = "pp-ocrv5_mobile_det.onnx";
const REC_MODEL: &str = "en_pp-ocrv5_mobile_rec.onnx";
const DICT_FILE: &str = "ppocrv5_en_dict.txt";

/// Turns image bytes into recognized text. A trait (not a concrete type)
/// so callers -- `safeprompt-file-inspector`'s image dispatch,
/// `safeprompt-inspector`'s Inspector -- depend on a stable, tiny surface
/// rather than on `oar-ocr` directly; swapping engines later (a different
/// OCR backend, a platform-native API on some target) means implementing
/// this trait again, not touching every call site.
pub trait OcrEngine: Send + Sync {
    /// `image_bytes` is a whole encoded image file (PNG/JPEG/BMP/TIFF/WebP/
    /// GIF -- whatever the `image` crate's format-sniffing recognizes), not
    /// raw pixels. Returns `Ok(String::new())` -- not an error -- when the
    /// image decodes fine but no text is found; that's a legitimate outcome
    /// (a photo with no text in it), not a failure. Returns `Err` only when
    /// the bytes can't be decoded as an image at all, or the OCR pipeline
    /// itself fails/panics on this input.
    fn extract_text(&self, image_bytes: &[u8]) -> anyhow::Result<String>;
}

/// [`OcrEngine`] backed by `oar-ocr`'s PP-OCR pipeline (detection model
/// finds text regions, recognition model reads each region, both run
/// on-device via the `ort` ONNX Runtime bindings -- see this module's doc
/// comment for model provisioning).
pub struct OarOcrEngine {
    inner: OAROCR,
}

impl OarOcrEngine {
    /// Builds the pipeline using `oar-ocr`'s auto-download registry (see
    /// module doc comment) -- the common case for every edition that ships
    /// this crate's `auto-download` Cargo feature (enabled unconditionally
    /// today; revisit if an offline-install SKU needs `new_from_paths`
    /// below instead).
    pub fn new_with_auto_download() -> anyhow::Result<Self> {
        resolve_and_init_dylib();
        let inner = OAROCRBuilder::new(DET_MODEL.to_string(), REC_MODEL.to_string(), DICT_FILE.to_string())
            .build()
            .map_err(|e| anyhow::anyhow!("failed to build OCR pipeline (model download/load): {e}"))?;
        Ok(Self { inner })
    }

    /// Builds the pipeline from explicit local file paths instead of the
    /// auto-download registry -- for an offline/air-gapped install that
    /// bundles the ONNX model files alongside the Agent binary rather than
    /// fetching them on first run. Not wired into `apps/service` yet (real
    /// future work, tracked separately, not silently assumed done here).
    pub fn new_from_paths(det_model_path: &str, rec_model_path: &str, dict_path: &str) -> anyhow::Result<Self> {
        resolve_and_init_dylib();
        let inner = OAROCRBuilder::new(det_model_path.to_string(), rec_model_path.to_string(), dict_path.to_string())
            .build()
            .map_err(|e| anyhow::anyhow!("failed to build OCR pipeline from local model paths: {e}"))?;
        Ok(Self { inner })
    }
}

impl OcrEngine for OarOcrEngine {
    fn extract_text(&self, image_bytes: &[u8]) -> anyhow::Result<String> {
        let decoded = image::load_from_memory(image_bytes).map_err(|e| anyhow::anyhow!("not a recognizable image format: {e}"))?;
        let rgb = decoded.into_rgb8();

        // `predict` runs untrusted-shaped input (an attacker-controlled
        // upload/screenshot) through `oar-ocr`'s ONNX inference pipeline --
        // a dependency with its own native ONNX Runtime code underneath.
        // Same defense-in-depth already used for `anydoc` in
        // safeprompt-file-inspector: a panic deep inside becomes a clean
        // error for this one image, not a crashed Agent process.
        let predict_result = catch_unwind(AssertUnwindSafe(|| self.inner.predict(vec![rgb])))
            .map_err(|_| anyhow::anyhow!("OCR pipeline panicked while processing this image (caught, not propagated)"))?;
        let results = predict_result.map_err(|e| anyhow::anyhow!("OCR inference failed: {e}"))?;

        let Some(page) = results.into_iter().next() else {
            return Ok(String::new());
        };

        let mut text = String::new();
        for region in &page.text_regions {
            if let Some((recognized, _confidence)) = region.text_with_confidence() {
                if !recognized.is_empty() {
                    if !text.is_empty() {
                        text.push('\n');
                    }
                    text.push_str(&recognized);
                }
            }
        }
        Ok(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeEngine;
    impl OcrEngine for FakeEngine {
        fn extract_text(&self, _image_bytes: &[u8]) -> anyhow::Result<String> {
            Ok("stubbed text".to_string())
        }
    }

    #[test]
    fn the_trait_object_boundary_is_usable_as_dyn() {
        // Compile-time proof this trait is object-safe and Send + Sync --
        // the exact shape `Inspector`/`file_inspector` need to hold it
        // behind an `Arc<dyn OcrEngine>` field.
        let engine: Box<dyn OcrEngine> = Box::new(FakeEngine);
        let text = engine.extract_text(b"anything").unwrap();
        assert_eq!(text, "stubbed text");
    }

    fn assert_send_sync<T: Send + Sync>() {}
    #[test]
    fn oar_ocr_engine_is_send_and_sync() {
        assert_send_sync::<OarOcrEngine>();
    }

    #[test]
    fn garbage_bytes_are_a_clean_error_not_a_panic() {
        // Doesn't need a built OarOcrEngine (that requires a real model
        // load) -- exercises the same decode step every engine will need,
        // via a minimal harness that mirrors `OarOcrEngine::extract_text`'s
        // own decode-first behavior.
        let result = image::load_from_memory(b"this is not an image at all, just text bytes");
        assert!(result.is_err(), "garbage bytes must not decode as an image");
    }

    // ── Real, opt-in, model-downloading integration test ────────────────
    //
    // Gated behind SAFEPROMPT_TEST_OCR_LIVE=1 (same pattern as the
    // postgres-backend test in safeprompt-storage): it downloads real
    // ~12MB ONNX models over the network on first run and performs real
    // CPU inference, which is too slow/network-dependent for a normal
    // `cargo test` run but must exist and be run at least once to prove
    // this crate's core claim -- that oar-ocr genuinely extracts text from
    // a real image -- isn't faked.
    #[test]
    fn real_oar_ocr_extracts_real_text_from_a_rendered_image() {
        if std::env::var("SAFEPROMPT_TEST_OCR_LIVE").as_deref() != Ok("1") {
            eprintln!("skipping: set SAFEPROMPT_TEST_OCR_LIVE=1 to run (downloads real ONNX models)");
            return;
        }

        let Some(png_bytes) = render_test_png("CONFIDENTIAL SECRET 42") else {
            eprintln!("skipping: no usable system font found to render the test image");
            return;
        };
        let engine = OarOcrEngine::new_with_auto_download().expect("failed to build real OCR pipeline");
        let text = engine.extract_text(&png_bytes).expect("OCR extraction failed");
        let upper = text.to_uppercase();
        assert!(
            upper.contains("CONFIDENTIAL") || upper.contains("SECRET"),
            "expected real OCR to recognize the rendered text, got: {text:?}"
        );
    }

    /// Renders `text` onto a real in-memory bitmap using a real installed
    /// system font -- a genuine PNG with genuine anti-aliased glyphs, not a
    /// fabricated/stubbed fixture -- and returns its PNG-encoded bytes.
    /// `None` if no usable font file could be found on this machine (this
    /// test is opt-in and environment-dependent already; a missing font is
    /// reported as a skip, not faked with placeholder pixels).
    fn render_test_png(text: &str) -> Option<Vec<u8>> {
        use ab_glyph::{FontRef, PxScale};
        use image::{Rgb, RgbImage};
        use imageproc::drawing::draw_text_mut;

        let candidate_fonts = [
            r"C:\Windows\Fonts\arial.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
            "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
            "/System/Library/Fonts/Supplemental/Arial.ttf",
        ];
        let font_bytes = candidate_fonts.iter().find_map(|p| std::fs::read(p).ok())?;
        let font = FontRef::try_from_slice(&font_bytes).ok()?;

        let mut img = RgbImage::from_pixel(600, 120, Rgb([255, 255, 255]));
        draw_text_mut(&mut img, Rgb([0, 0, 0]), 20, 30, PxScale::from(48.0), &font, text);

        let mut png_bytes = Vec::new();
        image::DynamicImage::ImageRgb8(img)
            .write_to(&mut std::io::Cursor::new(&mut png_bytes), image::ImageFormat::Png)
            .ok()?;
        Some(png_bytes)
    }
}
