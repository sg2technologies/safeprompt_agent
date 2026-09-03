// Authenticode signature checking, via PowerShell's built-in
// `Get-AuthenticodeSignature` cmdlet rather than a hand-rolled WinVerifyTrust
// FFI binding. Deliberate choice for a security-critical trust check: a raw
// WinTrust binding means unsafe Win32 struct layouts this codebase would own
// and could get subtly wrong (a false-accept here defeats the entire point);
// `powershell.exe` ships on every Windows install by default (unlike
// `signtool.exe`, a Windows SDK / Visual Studio Build Tools component this
// shipped product can't assume a customer has), and `Get-AuthenticodeSignature`
// already wraps the exact same WinVerifyTrust call correctly, tested by
// Microsoft, not by us — same reasoning that led the Python Control Plane to
// shell out to the real `license-tool` binary for Ed25519 signing rather than
// reimplementing serde_json's canonical byte serialization natively.
//
// Cross-platform note, deliberately NOT special-cased: Authenticode is a
// Windows-only concept (Linux/macOS binaries are never Authenticode-signed
// at all, so `IntegrityManifest::expected_signer_thumbprint` should simply
// never be set on a manifest issued for a Linux/macOS binary). On a
// non-Windows host this module's calls to `powershell.exe` fail with
// `CouldNotCheck` (the binary doesn't exist there), which naturally
// propagates as a verification *failure* rather than a silent skip --
// deliberately fail-closed, matching this crate's existing posture ("a
// manifest that's present and doesn't verify -> refuse to run") rather than
// quietly treating a misconfigured/inapplicable signer-pin as vacuously
// satisfied. Confirmed by actually building and testing this crate on real
// Linux (WSL/Ubuntu 24.04) during the Linux packaging pass, not assumed.

use serde::Deserialize;
use std::path::Path;
use std::process::Command;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AuthenticodeError {
    #[error("could not check the Authenticode signature: {0}")]
    CouldNotCheck(String),
    #[error("file is not Authenticode-signed")]
    NotSigned,
    #[error("Authenticode signature status is {0} (expected Valid) — the file may have been tampered with")]
    InvalidStatus(String),
    #[error("signed by certificate thumbprint {actual}, expected {expected}")]
    UnexpectedSigner { actual: String, expected: String },
}

#[derive(Debug, Deserialize)]
struct RawSignatureCheck {
    #[serde(rename = "Status")]
    status: String,
    #[serde(rename = "Thumbprint")]
    thumbprint: Option<String>,
}

#[derive(Debug)]
pub struct SignatureInfo {
    /// Uppercase hex SHA1 thumbprint of the signing certificate.
    pub thumbprint: String,
}

/// Checks `path`'s Authenticode signature. `Ok` only for `Status: Valid`
/// (a full, unbroken chain of trust) — `HashMismatch` (tampered file),
/// `NotSigned`, `NotTrusted`, and every other `Get-AuthenticodeSignature`
/// status are all treated as failures, not partial success.
pub fn check_signature(path: &Path) -> Result<SignatureInfo, AuthenticodeError> {
    let path_str = path.to_string_lossy().replace('\'', "''");
    // `.Status` is a `SignatureStatus` *enum* -- ConvertTo-Json serializes
    // an un-cast enum as its underlying integer ordinal (`1`, not
    // `"NotSigned"`), which silently broke this until `.ToString()` forces
    // it to the name. A real gotcha caught by the unit tests below, not a
    // hypothetical one.
    let script = format!(
        "Get-AuthenticodeSignature -LiteralPath '{path_str}' | \
         Select-Object @{{Name='Status';Expression={{$_.Status.ToString()}}}}, @{{Name='Thumbprint';Expression={{$_.SignerCertificate.Thumbprint}}}} | \
         ConvertTo-Json -Compress"
    );

    let output = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output()
        .map_err(|e| AuthenticodeError::CouldNotCheck(e.to_string()))?;

    if !output.status.success() {
        return Err(AuthenticodeError::CouldNotCheck(String::from_utf8_lossy(&output.stderr).trim().to_string()));
    }

    let parsed: RawSignatureCheck = serde_json::from_slice(&output.stdout)
        .map_err(|e| AuthenticodeError::CouldNotCheck(format!("unexpected PowerShell output: {e}")))?;

    match parsed.status.as_str() {
        "Valid" => Ok(SignatureInfo {
            thumbprint: parsed.thumbprint.unwrap_or_default().to_uppercase(),
        }),
        "NotSigned" => Err(AuthenticodeError::NotSigned),
        other => Err(AuthenticodeError::InvalidStatus(other.to_string())),
    }
}

/// Checks that `path` has a valid Authenticode signature *and* that it was
/// signed by the specific certificate `expected_thumbprint` names — a valid
/// signature from *any* certificate isn't a meaningful security property (an
/// attacker can get their own code-signing certificate), pinning to a known
/// signer is.
pub fn verify_signer(path: &Path, expected_thumbprint: &str) -> Result<(), AuthenticodeError> {
    let info = check_signature(path)?;
    let expected = expected_thumbprint.to_uppercase();
    if info.thumbprint != expected {
        return Err(AuthenticodeError::UnexpectedSigner { actual: info.thumbprint, expected });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    // These only exercise the failure paths that don't depend on a trusted
    // signing certificate being installed on the test machine — the
    // positive path (a validly signed *and* Windows-trusted binary) needs a
    // real certificate trusted in the machine/user store, which is exactly
    // what agent/scripts/test-authenticode-verification.ps1 sets up and
    // tears down around the real service/watchdog binaries; that's the live
    // proof, not a unit test fixture.

    #[test]
    fn a_plain_non_pe_file_is_rejected_not_silently_accepted() {
        // A raw extensionless temp file isn't even a recognizable signable
        // format, so Get-AuthenticodeSignature reports `UnknownError` here,
        // not `NotSigned` (that status is specifically for a real,
        // recognizable-but-unsigned PE) -- a real distinction discovered
        // while writing this test, not an assumption. Either way it must be
        // rejected, which is the actual property that matters.
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(b"just some bytes, never Authenticode-signed").unwrap();
        file.flush().unwrap();
        // Windows won't let another process (powershell.exe) open a file
        // this process still holds a handle to -- `into_temp_path()` closes
        // our handle while keeping the file on disk (and still cleans it up
        // on drop), which a plain NamedTempFile can't do.
        let path = file.into_temp_path();

        assert!(check_signature(&path).is_err());
    }

    #[test]
    fn a_nonexistent_file_is_a_could_not_check_error_not_a_panic() {
        let result = check_signature(Path::new("C:\\this\\path\\does\\not\\exist.exe"));
        assert!(matches!(result, Err(AuthenticodeError::CouldNotCheck(_))));
    }

    #[test]
    fn verify_signer_on_an_unsigned_file_is_rejected_not_silently_accepted() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(b"unsigned").unwrap();
        file.flush().unwrap();
        let path = file.into_temp_path();

        assert!(verify_signer(&path, "AABBCCDD").is_err());
    }
}
