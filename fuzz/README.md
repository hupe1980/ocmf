# Fuzzing

```console
cargo install cargo-fuzz
cargo +nightly fuzz run parse
cargo +nightly fuzz run round_trip
cargo +nightly fuzz run der
cargo +nightly fuzz run key
cargo +nightly fuzz run verify
```

Seed the corpus from the real records the crate ships:

```console
mkdir -p fuzz/corpus/parse
cargo run -q -p xtask -- corpus-report   # prints where the fixture lives
python3 - <<'PY'
import json, pathlib
d = json.load(open("ocmf/tests/corpus/records.json"))
out = pathlib.Path("fuzz/corpus/parse"); out.mkdir(parents=True, exist_ok=True)
for i, e in enumerate(d["entries"]):
    (out / f"{i:04d}.ocmf").write_text(e["record"])
PY
```

`round_trip` is the target that matters most: it asserts the property the whole
design exists to make true, on inputs nobody wrote deliberately.

`der` asserts that a signature read out and written back is the same two
scalars, in canonical DER. A writer that saturates a length does not emit
garbage, it emits a *different, well-formed* structure — which is why the
assertion is a round trip and not a length check (D31).
