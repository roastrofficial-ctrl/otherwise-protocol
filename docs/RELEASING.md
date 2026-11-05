# Alpha release checklist and publication

Target: `v0.1.0-alpha.1`. This is a release-engineering pass over the approved Solo profile, not a new protocol generation. Publication requires explicit maintainer approval. No script here pushes, creates a hosted service, publishes a package or creates a GitHub release.

## Local candidate checklist

- [x] Standalone repository, own licence/security policy, no parent imports or required external project.
- [x] Public README and synthetic same-Capsule check-in/expiry/release/export/Python/PHP demonstration.
- [x] Existing runtime logic, schema and fixed fixture bytes checked against `build/compatibility.json`; only the reference version marker changes.
- [x] Dependencies frozen by base digests and Python/Debian hashes; public supplied notices retained.
- [x] Working-tree secret/contact/certificate review and explicitly labelled fixture exceptions.
- [x] Preflight Python/Docker/PHP conformance and demo executed; see the report for exact results.
- [x] Final candidate commit and annotated local tag prepared locally; verify that `git describe --exact-match --tags` reports the target and the tree is clean.
- [x] Independent clean candidate clone passed; final-tag recheck evidence is supplied with the handoff.
- [ ] Source/wheel packaging: inspect `dist/SHA256SUMS` and the handoff result; never infer comparison success from this command.
- [ ] Explicit approval to publish; repository creation, push, private reporting setup and GitHub release happen afterward.

The final Git/tag/clone/audit status is reported in the release handoff. A checklist command being documented does not mean it ran. A Git tag annotation is unsigned unless deliberately signed with a maintainer-owned key; this preparation does not generate a signing key or claim a signed release.

```sh
python3 scripts/audit.py
git status --short
git describe --exact-match --tags
./scripts/clean-check.sh v0.1.0-alpha.1 > dist/clean-check.log 2>&1
./scripts/package-release.sh v0.1.0-alpha.1
```

The release audit needs Python 3 (stdlib only) and Git on the host; end-user conformance/demo use Docker. `clean-check.sh` makes an independent clone without Git hardlinks, verifies the revision, removes its origin, rebuilds without layer reuse, runs the full suites and runs the demo. It deletes its temporary clone afterward. `dist/` is ignored; create it before redirecting a log there. No global Docker cleanup is performed.

## Publishing commands — only after explicit approval

Run from the standalone protocol repository, with GitHub CLI authenticated as a maintainer. The commands assume the named GitHub repository does not already exist and no `origin` is configured. If it already exists, omit creation and set `origin` to that repository after reviewing it. No force-push or moving an existing public tag is intended.

```sh
set -eu
REPO=roastrofficial-ctrl/otherwise-protocol
TAG=v0.1.0-alpha.1

git status --short
test "$(git rev-parse "$TAG^{commit}")" = "$(git rev-parse HEAD)"
python3 scripts/audit.py
./scripts/package-release.sh "$TAG"

gh repo create "$REPO" --public --source=. --remote=origin
gh api --method PUT "repos/$REPO/private-vulnerability-reporting"
git push -u origin main
git push origin "$TAG"
gh release create "$TAG" dist/*.tar.gz dist/*.whl dist/SHA256SUMS \
  --repo "$REPO" --prerelease --verify-tag \
  --title 'Otherwise Protocol v0.1.0-alpha.1' --notes-file RELEASE_NOTES.md
```

Confirm this repository's private vulnerability-reporting form is available, README links work after publication, assets match SHA256SUMS, and a fresh public clone runs the documented commands. Do not upload demo key files, databases, TLS files, local configuration or the entire working directory. Package-index publication and deployment are outside this alpha assignment.
