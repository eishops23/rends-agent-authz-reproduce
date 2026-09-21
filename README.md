# Agent authorization evidence — reproduction harness

This repository is a mirror of two directories from a private evidence repository:

    reproduce/   the verifier, the acceptance suite, the capture scripts, and the captured bundles
    harness/     the five modules reproduce/ imports (chain, ledger, scenarios, rfc3161, redact)

They are published as siblings because that is the shape the code expects: scripts under
`reproduce/l5-adapter/` import `../../harness/...`. Flattening them would mean editing the
verifier, and the verifier is the file a skeptic is supposed to read unmodified.

Start at `reproduce/README.md`, then run `reproduce/l5-adapter/decision-acceptance.sh`.
Read case 5 first. Nothing here calls AWS.

The AWS account id in the ARNs belongs to a lab account and is published deliberately. The
bundles are not redacted and must not be: each bundle's root commits to its exact bytes, so
editing one to improve its own description would destroy the property that makes it evidence.
