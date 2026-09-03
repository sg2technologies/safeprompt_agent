# macOS packaging (untested — no macOS machine available)

Everything in this directory is a documented-correct starting point, not a
verified artifact. Windows Service integration and the Linux systemd unit
were both live-tested against the real thing in this session (real SCM,
real systemd via WSL/Ubuntu); this macOS path could only be authored and
checked for internal consistency (the plist's XML well-formedness, the
`cargo build --target x86_64-apple-darwin`/`aarch64-apple-darwin` target
triples being real Rust target names) — nothing here has actually been
built, signed, notarized, or loaded by `launchd` on a real Mac.

## 1. Build

Cross-compiling macOS binaries from Windows/Linux isn't realistic for a
Rust project with this many native dependencies (rustls, sqlx/sqlite,
rcgen) — build natively on macOS itself:

```
cargo build --release -p safeprompt-service -p safeprompt-watchdog
```

For both Intel and Apple Silicon, either build twice with `--target
x86_64-apple-darwin` / `--target aarch64-apple-darwin` and ship both, or
use `lipo` to fuse them into one universal binary:

```
lipo -create -output safeprompt-service target/x86_64-apple-darwin/release/safeprompt-service target/aarch64-apple-darwin/release/safeprompt-service
lipo -create -output safeprompt-watchdog target/x86_64-apple-darwin/release/safeprompt-watchdog target/aarch64-apple-darwin/release/safeprompt-watchdog
```

## 2. Code signing

macOS's equivalent of Authenticode (see `installer/sign.ps1` and the
Code Signing decision, 2026-07-30) is `codesign`, using a "Developer ID
Application" certificate from an Apple Developer account:

```
codesign --sign "Developer ID Application: SafePrompt Security Team (TEAMID)" \
    --options runtime --timestamp safeprompt-service
codesign --sign "Developer ID Application: SafePrompt Security Team (TEAMID)" \
    --options runtime --timestamp safeprompt-watchdog
```

`--timestamp` is macOS's equivalent of the RFC 3161 timestamp
`installer/sign.ps1` applies on Windows: the signature stays valid after
the certificate itself expires. `--options runtime` opts into the Hardened
Runtime, required for notarization (next step).

Unlike Windows (where an enterprise-internal CA is a legitimate, fully
supported alternative to a commercial cert — see the Code Signing decision
for why both were built), macOS has no equivalent "bring your own internal
CA" path for LaunchDaemons distributed outside an MDM-pushed configuration
profile: a real Apple Developer ID is required for the best install
experience (no Gatekeeper warnings). An unsigned or ad-hoc-signed binary
still runs, but every user sees a Gatekeeper block on first launch that
requires an explicit System Settings override to bypass.

## 3. Notarization

Apple requires notarization (an automated malware scan performed by
Apple's own servers) for a smooth install experience — an app that's
signed but not notarized still triggers Gatekeeper friction. After
building the `.pkg` (next section):

```
xcrun notarytool submit SafePrompt.pkg --keychain-profile "safeprompt-notary" --wait
xcrun stapler staple SafePrompt.pkg
```

(`--keychain-profile` refers to credentials stored once via `xcrun
notarytool store-credentials` — an Apple ID + app-specific password or API
key, not something to hardcode into a build script.)

## 4. Package as a .pkg

```
pkgbuild --root payload/ \
    --scripts scripts/ \
    --identifier com.safeprompt.agent \
    --version 0.1.0 \
    --install-location / \
    SafePrompt.pkg
```

Where `payload/` mirrors the final filesystem layout (e.g.
`payload/Library/Application Support/SafePrompt/safeprompt-service`,
`.../safeprompt-watchdog`, `payload/Library/LaunchDaemons/
com.safeprompt.watchdog.plist` — see `com.safeprompt.watchdog.plist` in
this directory) and `scripts/postinstall` creates the least-privilege
`safeprompt` user/group and loads the LaunchDaemon, mirroring the Linux
`.deb`/`.rpm` postinst scriptlets exactly:

```bash
#!/bin/bash
# scripts/postinstall
if ! dscl . -read /Groups/safeprompt >/dev/null 2>&1; then
    dseditgroup -o create safeprompt
fi
if ! dscl . -read /Users/_safeprompt >/dev/null 2>&1; then
    sysadminctl -addUser _safeprompt -fullName "SafePrompt Agent" \
        -home /var/empty -shell /usr/bin/false
    dseditgroup -o edit -a _safeprompt -t user safeprompt
fi
chown -R _safeprompt:safeprompt "/Library/Application Support/SafePrompt"
launchctl load /Library/LaunchDaemons/com.safeprompt.watchdog.plist
exit 0
```

(macOS system account naming conventions prefer a leading underscore,
e.g. `_safeprompt`, for daemon-only accounts — adjust the LaunchDaemon
plist's `UserName`/`GroupName` to match whatever this script actually
creates.)

## Known gaps, stated plainly

- No macOS machine was available to actually build, sign, notarize, or run
  any of this.
- The postinstall script above is written to the same logic already proven
  correct on Linux (`agent/apps/watchdog/debian/postinst`), but macOS's
  `dscl`/`dseditgroup`/`sysadminctl` command syntax was not executed or
  verified.
- No CI/build pipeline exists yet to actually produce a universal binary
  or run this packaging end to end.
