default: ci

# Everything CI gates on, runnable locally.
ci: test lint house

# The full test suite, including the reference corpus.
test:
    cargo test --workspace --features "full,backend-openssl"

# The other CI jobs: every feature combination, the embedded build, the MSRV.
matrix:
    for f in "std" "std,verify,curve-p256" "std,verify,curves-pure" "full" "full,backend-openssl"; do \
        echo "── $f"; cargo test -q -p ocmf --no-default-features --features "$f"; \
    done

# The pure-Rust build, and the two targets that are not this machine.
test-pure:
    cargo test --workspace --features full
    cargo build -p ocmf --no-default-features \
        --features alloc,verify,curve-p256,sign,session,ocpp \
        --target thumbv7em-none-eabihf
    cargo build -p ocmf --features full --target wasm32-unknown-unknown

lint:
    cargo fmt --all -- --check
    cargo clippy --workspace --all-targets --features "full,backend-openssl" -- -D warnings
    RUSTDOCFLAGS="-D warnings" cargo doc --no-deps -p ocmf --features full

# The house rules: no floats, corpus statistics, and the conformance suite.
house:
    cargo xtask no-floats
    cargo xtask corpus-report
    cargo xtask conformance-gen
    git diff --exit-code conformance/suite.json
    cargo run -q -p ocmf-cli -- conformance conformance/suite.json

# The performance budget. Verification is roughly 50x the parse; the benchmarks
# exist to show where the time goes, not to chase a number.
bench:
    cargo bench -p ocmf --features "full,backend-openssl"

# Mutation testing where a surviving mutant is a wrong answer about money.
mutants:
    cargo mutants --package ocmf -- --features full,backend-openssl

# Re-fetch the pinned specs and check every table value exists in the code.
spec:
    cargo xtask spec-sync
    cargo xtask spec-coverage

msrv:
    cargo +1.88.0 check -p ocmf --features full

# What `release.yml` does before it publishes anything, minus the tag check.
# `--allow-dirty` because this is a rehearsal on a working tree; CI runs it on
# a clean checkout of the tag and without that flag.
release-check:
    cargo publish -p ocmf --dry-run --locked --allow-dirty
    cargo build -p ocmf-cli --release --features vendored-openssl
    ./target/release/ocmf curves
    ./target/release/ocmf conformance conformance/suite.json

# The website: http://127.0.0.1:1111, with live reload.
site:
    zola --root site serve

# What CI checks before deploying: dead links, then a full build.
site-check:
    zola --root site check
    zola --root site build

# Explain a record — the command this project exists for.
explain FILE:
    cargo run -q -p ocmf-cli -- explain {{FILE}}
