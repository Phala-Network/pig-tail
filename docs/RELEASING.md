# Release policy

Integrate tested changes into `main`. Development branches carry candidates;
long-term maintenance branches need a real compatibility requirement. Create an
immutable annotated version tag from a verified commit in `main` history.
Never move published tags or overwrite existing image versions.

Record the source commit, version/tag, relevant component/engine identities,
validation scope and published artifact digest. Component tests, final-image
checks and target deployment acceptance are separate results. Version metadata
alone does not establish release qualification.

Check existing workflows before pushing a tag. Pushes run source checks and do
not publish images. Publish the tag's GitHub Release first, then dispatch
`release-image.yml` with that tag. The Linux CPU runner verifies the published
Release, runs race tests and vet, builds the pinned Dockerfile once, tests the
final image with `scripts/image-smoke.py`, and publishes only after those checks
pass. It refuses an existing image tag. Read back and record the immutable
registry digest. CPU image checks do not qualify real dstack/NVML evidence;
verify that on the target before restoring traffic. Historical tag backfills
must match existing artifact source; they do not authorize a rebuild or deployment.

Keep release notes concise. Put raw logs and large build artifacts in release
assets or evidence storage; link to immutable records instead of duplicating
execution logs in the repository's landing page.
