# Releasing bifrost

A release is cut by the **Release** workflow (Actions → Release → Run workflow,
input e.g. `v0.2.0`). It:

1. runs `go vet` and the tests on the current `main`,
2. builds `Bifrost.xcframework` on macOS with `scripts/build-ios.sh` and zips it,
3. writes `Package.swift` with the URL and checksum of that zip
   (`scripts/update-package-swift.sh`), commits it as `Release v0.2.0` on `main`
   and pushes the tag `v0.2.0` together with it,
4. runs GoReleaser on that tag: binaries for linux/darwin × amd64/arm64,
   `.deb` packages, `SHA256SUMS` (including the framework zip) and
   `SHA256SUMS.minisig`, all attached to a GitHub release.

Do not push release tags by hand: `Package.swift` at a tag must already contain
the checksum of that tag's framework, which only the workflow knows.
If the run fails after the tag was pushed, delete the release and the tag and
run it again with the same version.

## One-time setup

1. Create a signing key on your own machine (never in CI, never in git):

   ```sh
   minisign -G -p minisign.pub -s minisign.key     # asks for a password
   ```

2. Commit the **public** key as `packaging/minisign.pub`.
3. Add two repository secrets (Settings → Secrets and variables → Actions):
   - `MINISIGN_SECRET_KEY`: the full contents of `minisign.key`
   - `MINISIGN_PASSWORD`: its password
4. Store `minisign.key` and its password in your password manager and delete the
   file. Losing it only means a new key and a new `minisign.pub`.

The workflow refuses to run while `packaging/minisign.pub` is missing.

## Swift Package Manager

Apps add the package `https://github.com/MichaelBMF/bifrost` with a version
rule (e.g. "Up to Next Minor" from `0.2.0`) and use the library product
`Bifrost` (`import Bifrost`). SPM downloads `Bifrost.xcframework.zip` from the
release and checks it against the checksum in `Package.swift`, so the app needs
neither Go nor gomobile. `main` between releases still has the `Package.swift`
of the last release.
