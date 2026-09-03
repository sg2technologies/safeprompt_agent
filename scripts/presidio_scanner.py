"""
Presidio/spaCy NER scanner — the Python side of the stdin/stdout protocol
`agent/crates/scanner` speaks to (see `protocol.rs` for the Rust-side
struct definitions this must stay byte-for-byte compatible with).

Deliberately standalone (does not import `backend/detection/`) so this one
file is everything a PyInstaller freeze needs — no FastAPI, no Mongo driver,
no unrelated backend dependencies riding along into the customer's runtime.
The entity-detection logic itself is intentionally the same shape as
`backend/detection/layer2_presidio.py` (same NLP engine config, same India
recognizers) so the two stay comparable as a golden-set reference — see
memory `safeprompt-edge-first-ml-detection`.

Wire format: each message (both directions) is a 4-byte big-endian length
prefix followed by that many bytes of UTF-8 JSON. Not newline-delimited —
scanned text can itself contain newlines.

Run standalone for a manual smoke test:
    python presidio_scanner.py
    (then feed it length-prefixed frames on stdin)

Freeze for distribution (2026-08-11: the plain `--onefile --name
presidio-scanner presidio_scanner.py` this comment used to say ran, but
does NOT produce a working exe on its own — PyInstaller's import scanner
can't see spaCy/presidio's own plugin-style dynamic loading, so the frozen
binary silently fails to find the en_core_web_sm model and presidio's own
config file at runtime. The `--collect-all` flags below were found by
actually running the frozen exe and fixing what broke, three separate
times, on 2026-08-11 — see memory `safeprompt-llm-verify-pass` and
`safeprompt-ner-scanner-gaps`. Use this exact command, including for CI
(`.github/workflows/release.yml`'s windows-msi job runs it verbatim):
    pyinstaller --onefile --name presidio-scanner \
        --collect-all en_core_web_sm --collect-all spacy \
        --collect-all thinc --collect-all presidio_analyzer \
        --distpath dist --clean -y presidio_scanner.py
"""

import json
import logging
import struct
import sys
import time
from pathlib import Path

logging.basicConfig(
    level=logging.WARNING,
    stream=sys.stderr,  # never write logs to stdout -- that's the protocol channel
    format="%(asctime)s presidio_scanner %(levelname)s: %(message)s",
)
logger = logging.getLogger("presidio_scanner")

PROTOCOL_VERSION = 1

_engine = None
_engine_attempted = False


def _build_engine():
    global _engine, _engine_attempted
    if _engine_attempted:
        return _engine
    _engine_attempted = True

    try:
        from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer
        from presidio_analyzer.nlp_engine import NlpEngineProvider
    except ImportError:
        logger.warning("presidio-analyzer not installed -- every scan will return no entities")
        return None

    try:
        # 2026-08-11: `spacy.load("en_core_web_sm")` (a bare package NAME)
        # resolves the model via Python package metadata -- entry points /
        # importlib.metadata -- which PyInstaller's frozen environment
        # doesn't preserve, even with the model's data files correctly
        # bundled via --collect-data. Live-caught: a frozen build with the
        # data present still logged "Model en_core_web_sm is not
        # installed. Downloading..." and then failed outright (no network,
        # no pip/uv in a frozen exe), corrupting the stdout protocol
        # channel with that download tool's own text output in the
        # process. Fixed by resolving the model's actual directory on disk
        # and passing that PATH instead of the bare name -- spacy.load()
        # accepts either, and a direct path never touches the
        # package-metadata lookup that breaks when frozen.
        try:
            import en_core_web_sm
            # The package dir itself isn't the model -- the actual
            # config.cfg/weights live in a versioned subdirectory
            # (en_core_web_sm-<version>/), which is exactly what this
            # package's own __init__.py's load() resolves via
            # load_model_from_init_py. Globbing rather than hardcoding a
            # version keeps this working across a spaCy model upgrade with
            # no code change here.
            pkg_dir = Path(en_core_web_sm.__file__).parent
            versioned_dirs = sorted(pkg_dir.glob("en_core_web_sm-*"))
            model_path = str(versioned_dirs[0]) if versioned_dirs else str(pkg_dir)
            logger.warning(
                "model path resolution: frozen=%s pkg_dir=%s pkg_dir_exists=%s pkg_dir_contents=%s versioned_dirs=%s model_path=%s",
                getattr(sys, "frozen", False), pkg_dir, pkg_dir.exists(),
                list(pkg_dir.iterdir()) if pkg_dir.exists() else "N/A",
                versioned_dirs, model_path,
            )
        except ImportError:
            model_path = "en_core_web_sm"  # dev/unfrozen fallback -- name-based resolution works fine unfrozen

        provider = NlpEngineProvider(
            nlp_configuration={
                "nlp_engine_name": "spacy",
                "models": [{"lang_code": "en", "model_name": model_path}],
            }
        )
        nlp_engine = provider.create_engine()

        pan_recognizer = PatternRecognizer(
            supported_entity="IN_PAN",
            patterns=[Pattern("PAN", r"\b[A-Z]{5}[0-9]{4}[A-Z]\b", 0.85)],
        )
        aadhaar_recognizer = PatternRecognizer(
            supported_entity="IN_AADHAAR",
            patterns=[Pattern("AADHAAR", r"\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b", 0.8)],
        )

        engine = AnalyzerEngine(nlp_engine=nlp_engine, supported_languages=["en"])
        engine.registry.add_recognizer(pan_recognizer)
        engine.registry.add_recognizer(aadhaar_recognizer)
        logger.info("Presidio analyzer ready (en_core_web_sm + India recognizers)")
        _engine = engine
        return engine
    except OSError as e:
        # 2026-08-11: this used to log a fixed, generic string here
        # regardless of the real OSError -- which meant a real, different
        # failure (spaCy's config-driven component registry not fully
        # populated in a frozen build, discovered the hard way chasing this
        # exact hardcoded message as if it were the real error) looked
        # identical to "model genuinely missing." Logging `e` itself is
        # the fix that would have saved that detour.
        logger.warning("spaCy model 'en_core_web_sm' could not be loaded (%s): %s", type(e).__name__, e)
    except Exception:
        logger.exception("Presidio engine failed to initialise")
    return None


def _read_frame(stream) -> bytes:
    header = stream.read(4)
    if len(header) < 4:
        raise EOFError("stdin closed")
    (length,) = struct.unpack(">I", header)
    payload = stream.read(length)
    if len(payload) < length:
        raise EOFError("stdin closed mid-frame")
    return payload


def _write_frame(stream, payload: bytes) -> None:
    stream.write(struct.pack(">I", len(payload)))
    stream.write(payload)
    stream.flush()


def _handle_health(request: dict) -> dict:
    # Touching the engine here (not lazily on first "ner" request) means a
    # successful health-check response really does mean "ready to scan
    # fast," not just "process started" -- the Rust side's generous startup
    # timeout is spent here, not on the caller's first real request.
    _build_engine()
    return {
        "version": PROTOCOL_VERSION,
        "request_id": request.get("request_id", "health"),
        "entities": [],
        "warnings": [] if _engine is not None else ["presidio_unavailable"],
        "duration_ms": 0,
    }


def _handle_ner(request: dict) -> dict:
    started = time.monotonic()
    text = request.get("text", "")
    engine = _build_engine()

    entities = []
    warnings = []
    if engine is None:
        warnings.append("presidio_unavailable")
    else:
        try:
            # score_threshold=0.4 added 2026-08-11: live-caught false
            # positive testing against real documents -- "Q3" (a plain
            # business-quarter reference) matched Presidio's built-in
            # US_DRIVER_LICENSE pattern recognizer with a low confidence
            # score and got redacted anyway, since nothing here filtered on
            # `result.score` even though Presidio was already computing it.
            # Pattern-only recognizers on short alphanumeric tokens (driver
            # licenses, some ID formats) tend to score low without
            # surrounding context; genuine spaCy NER hits (PERSON/LOCATION/
            # DATE_TIME, the entities that actually matter here) score much
            # higher. 0.4 is a starting point, not a carefully swept
            # value -- revisit if real usage shows it's cutting a genuine
            # finding, or letting another noisy one through.
            for result in engine.analyze(text=text, language="en", score_threshold=0.4):
                entities.append(
                    {
                        "entity_type": result.entity_type,
                        "start": result.start,
                        "end": result.end,
                        "score": round(result.score, 2),
                        "match": text[result.start : result.end],
                    }
                )
        except Exception:
            logger.exception("Presidio analyze failed")
            warnings.append("analyze_failed")

    return {
        "version": PROTOCOL_VERSION,
        "request_id": request.get("request_id", ""),
        "entities": entities,
        "warnings": warnings,
        "duration_ms": round((time.monotonic() - started) * 1000),
    }


def main() -> None:
    stdin = sys.stdin.buffer
    stdout = sys.stdout.buffer

    while True:
        try:
            frame = _read_frame(stdin)
        except EOFError:
            break

        try:
            request = json.loads(frame.decode("utf-8"))
        except json.JSONDecodeError:
            logger.warning("received a non-JSON frame, ignoring it")
            continue

        layer = request.get("layer", "ner")
        if layer == "health":
            response = _handle_health(request)
        else:
            response = _handle_ner(request)

        _write_frame(stdout, json.dumps(response).encode("utf-8"))


if __name__ == "__main__":
    main()
