# Releasing

Set variables:

    export VERSION=X.Y.Z
    export GPG_KEY=E7ADD9914E260E8B35DFB50665FDE935573ACDA6

Update version numbers:

    vim -p Cargo.toml
    cargo update

Update changelog:

    vim CHANGELOG.md

Commit & tag:

    git commit -S${GPG_KEY} -m "Release v${VERSION}"
    git tag -s -u ${GPG_KEY} v${VERSION} -m "Version ${VERSION}"

Publish:

    cargo publish
    git push && git push --tags
