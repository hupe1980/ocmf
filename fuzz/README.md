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
python3 - <<'PY'
import json, pathlib
d = json.load(open("ocmf/tests/corpus/records.json"))
out = pathlib.Path("fuzz/corpus/parse"); out.mkdir(parents=True, exist_ok=True)
for i, e in enumerate(d["entries"]):
    (out / f"{i:04d}.ocmf").write_text(e["record"])
PY
```

| Target | Asserts |
|---|---|
| `parse` | parsing under every profile never panics or allocates without bound |
| `round_trip` | a parsed record prints back to its exact input, and its signed span matches a naive `split('|')` whenever no pipe sits inside a string |
| `der` | a signature read and re-written as canonical DER reads back as the same two scalars — a round trip, because a length bug can produce a different but well-formed structure |
| `key` | `PublicKey::from_bytes`, `from_text` and `from_oca` never panic |
| `verify` | verification against a fixed corpus key never panics |
