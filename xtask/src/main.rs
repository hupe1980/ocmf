//! Repository chores that CI enforces.
//!
//! Each of these exists because a promise in the README would otherwise be a
//! promise nobody checks:
//!
//! - `no-floats`  — "money is never a float", proved over the library sources.
//! - `spec-coverage` — every value in the specification's tables is represented
//!   in code, checked against the vendored specification itself.
//! - `corpus-report` — reproduces the field measurements the design rests on.
//! - `spec-sync` — re-fetches the pinned sources and reports drift, including
//!   the OCA application note, which is a PDF and is therefore pinned by
//!   content hash rather than by commit.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use sha2::Digest as _;

mod conformance;

/// Lower-case hex, for a content pin.
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

fn main() -> Result<()> {
    let task = std::env::args().nth(1);
    match task.as_deref() {
        Some("no-floats") => no_floats(),
        Some("spec-coverage") => spec_coverage(),
        Some("corpus-report") => corpus_report(),
        Some("spec-sync") => spec_sync(),
        Some("conformance-gen") => conformance::generate(&root()),
        Some("ci") => {
            no_floats()?;
            corpus_report()?;
            // `spec-coverage` needs `specs/`, which is not present in a clean
            // clone; it is a separate CI job that runs `spec-sync` first.
            Ok(())
        }
        _ => {
            eprintln!(
                "usage: cargo xtask <no-floats|spec-coverage|corpus-report|spec-sync|conformance-gen|ci>"
            );
            bail!("no task given");
        }
    }
}

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask lives one level below the workspace root")
        .to_path_buf()
}

fn rust_sources(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d).with_context(|| format!("reading {}", d.display()))? {
            let path = entry?.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }
    out.sort();
    Ok(out)
}

/// A meter reading is money, and a binary float cannot hold `0.1`.
fn no_floats() -> Result<()> {
    let lib = root().join("ocmf/src");
    let mut offences = Vec::new();
    for file in rust_sources(&lib)? {
        let text = std::fs::read_to_string(&file)?;
        for (n, line) in text.lines().enumerate() {
            // Doc comments and prose may say "f64" — the point is code.
            let code = line.trim_start();
            if code.starts_with("//") {
                continue;
            }
            for pat in ["f32", "f64"] {
                if let Some(i) = code.find(pat) {
                    let before = code[..i].chars().next_back();
                    let after = code[i + 3..].chars().next();
                    let is_ident =
                        |c: Option<char>| c.is_some_and(|c| c.is_alphanumeric() || c == '_');
                    if !is_ident(before) && !is_ident(after) {
                        offences.push(format!(
                            "{}:{}: {}",
                            file.strip_prefix(root()).unwrap_or(&file).display(),
                            n + 1,
                            code.trim()
                        ));
                    }
                }
            }
        }
    }
    if offences.is_empty() {
        println!("no-floats: clean ({} files)", rust_sources(&lib)?.len());
        return Ok(());
    }
    for o in &offences {
        eprintln!("  {o}");
    }
    bail!(
        "{} float(s) in the library. A meter reading is money; use rust_decimal::Decimal",
        offences.len()
    );
}

/// Every value in the specification's closed tables must appear in the code.
///
/// The specification is the oracle for completeness, mechanically: if S.A.F.E.
/// adds an identification type or a curve, this fails until the code has it.
fn spec_coverage() -> Result<()> {
    let spec = root().join("specs/OCMF-Open-Charge-Metering-Format/OCMF-en.md");
    if !spec.exists() {
        bail!(
            "{} not found — run `cargo xtask spec-sync` first",
            spec.display()
        );
    }
    let text = std::fs::read_to_string(&spec)?;
    let sources: String = rust_sources(&root().join("ocmf/src"))?
        .into_iter()
        .map(|p| std::fs::read_to_string(p).unwrap_or_default())
        .collect();

    // Identifiers the tables define, harvested from the first column of every
    // table row that looks like a closed value set.
    let mut wanted: BTreeSet<String> = BTreeSet::new();
    for line in text.lines() {
        let Some(cell) = line.strip_prefix("| ") else {
            continue;
        };
        let first = cell.split('|').next().unwrap_or("").trim();
        let looks_like_a_value = !first.is_empty()
            && first.len() <= 32
            && first
                .chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
            && first.chars().any(|c| c.is_ascii_alphabetic())
            && first.len() > 2;
        if looks_like_a_value {
            wanted.insert(first.to_string());
        }
    }
    // Signature algorithms are spelled out in Table 22.
    for line in text.lines() {
        if let Some(i) = line.find("ECDSA-") {
            let ident: String = line[i..]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '-')
                .collect();
            if ident.ends_with("SHA256") {
                wanted.insert(ident);
            }
        }
    }

    // Table 9 lists meter manufacturers and models. It is informative — a
    // catalogue of who has shipped OCMF, not a value set an implementation is
    // supposed to enumerate — so its rows are excluded by name rather than by
    // a heuristic that would quietly grow to cover real omissions too.
    const INFORMATIVE: &[&str] = &["NZR"];

    let mut missing = Vec::new();
    for value in &wanted {
        if INFORMATIVE.contains(&value.as_str()) {
            continue;
        }
        if !sources.contains(value.as_str()) {
            missing.push(value.clone());
        }
    }
    if missing.is_empty() {
        println!(
            "spec-coverage: all {} table values from the vendored specification are represented",
            wanted.len()
        );
        return Ok(());
    }
    for m in &missing {
        eprintln!("  missing: {m}");
    }
    bail!(
        "{} value(s) from the specification's tables have no representation in the code",
        missing.len()
    );
}

/// Reproduces the field measurements the design rests on.
fn corpus_report() -> Result<()> {
    let fixture = root().join("ocmf/tests/corpus/records.json");
    let raw = std::fs::read_to_string(&fixture)
        .with_context(|| format!("reading {}", fixture.display()))?;
    // Counted with the same crude scan the original study used, so that this
    // report is independent of the crate's own parser.
    let records = raw.matches("\"record\":").count();
    let verified = raw.matches("\"openssl_verified\": true").count();
    let not_verified = raw.matches("\"openssl_verified\": false").count();
    let no_verdict = raw.matches("\"openssl_verified\": null").count();
    println!("corpus-report (from tests/corpus/records.json)");
    println!("  records                     {records}");
    println!("  authentic  (OpenSSL)        {verified}");
    println!("  not authentic (OpenSSL)     {not_verified}");
    println!("  no verdict (no/bad key)     {no_verdict}");
    println!();
    println!("  The per-field statistics are asserted by `cargo test -p ocmf --test corpus`,");
    println!("  in `the_measurements_that_shaped_the_design_still_hold`.");
    Ok(())
}

/// Re-fetches the pinned specification sources and reports drift.
fn spec_sync() -> Result<()> {
    const PINS: &[(&str, &str, &str)] = &[
        (
            "OCMF-Open-Charge-Metering-Format",
            "https://github.com/SAFE-eV/OCMF-Open-Charge-Metering-Format.git",
            "34c4add5c3363e04d0468671c53b31ae3341bb17",
        ),
        (
            "transparenzsoftware",
            "https://github.com/SAFE-eV/transparenzsoftware.git",
            "def928b9ec5fee05b7b6815b343df65e77e99be8",
        ),
        // The original German v1.0 document (2019), for archaeology on the
        // 0.x/1.0-era fields that deployed hardware was built against.
        (
            "ocmf-v1.0-de",
            "https://github.com/SAFE-eV/OCMF.git",
            "f87c1e03c2d1273d046ca7f5443d7e04d3e33f27",
        ),
    ];

    /// Sources that are not git repositories, pinned by content hash.
    ///
    /// A PDF has no commit to check out, so the pin *is* the bytes: a silent
    /// republication under the same URL changes the hash and fails here, which
    /// is the same guarantee the git pins give.
    const FILES: &[(&str, &str, &str)] = &[(
        "oca/signed_meter_values-v10.pdf",
        "https://openchargealliance.org/wp-content/uploads/2025/05/signed_meter_values-v10-1.pdf",
        "9cd628544c8e4feda3fa23421613fd129d509de582464f414f4fb979c9914a6f",
    )];
    let specs = root().join("specs");
    std::fs::create_dir_all(&specs)?;
    let git = |dir: &Path, args: &[&str]| -> Result<std::process::Output> {
        let out = Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(args)
            .output()
            .with_context(|| format!("running git {}", args.join(" ")))?;
        Ok(out)
    };
    let mut drifted = Vec::new();
    for (name, url, pin) in PINS {
        let dir = specs.join(name);
        if !dir.exists() {
            println!("spec-sync: cloning {name}");
            let status = Command::new("git")
                .args(["clone", "--quiet", url])
                .arg(&dir)
                .status()?;
            if !status.success() {
                bail!("cloning {url} failed");
            }
        } else {
            let out = git(&dir, &["fetch", "--quiet", "origin"])?;
            if !out.status.success() {
                bail!("fetching {url} failed");
            }
        }

        // Check the working tree *out at the pin*. Without this the tree is at
        // whatever upstream's HEAD happens to be, so `spec-coverage` — which
        // reads these files as its oracle — would silently be measuring the
        // code against a specification revision nobody reviewed.
        let out = git(&dir, &["checkout", "--quiet", "--detach", pin])?;
        if !out.status.success() {
            bail!(
                "{name}: cannot check out the pin {}: {}",
                &pin[..8],
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }

        let head = git(&dir, &["rev-parse", "origin/HEAD"])?;
        let head = String::from_utf8_lossy(&head.stdout).trim().to_string();
        if head.is_empty() {
            println!(
                "  {name}: at the pin ({}); could not read origin/HEAD",
                &pin[..8]
            );
        } else if head == *pin {
            println!("  {name}: at the pin ({}), and upstream agrees", &pin[..8]);
        } else {
            drifted.push(format!(
                "  {name}: checked out at the pin ({}); upstream has moved to {}",
                &pin[..8],
                &head[..8.min(head.len())],
            ));
        }
    }
    for (path, url, sha) in FILES {
        let dest = specs.join(path);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        if !dest.exists() {
            println!("spec-sync: downloading {path}");
            let status = Command::new("curl")
                .args([
                    "--fail",
                    "--silent",
                    "--show-error",
                    "--location",
                    url,
                    "-o",
                ])
                .arg(&dest)
                .status();
            match status {
                Ok(s) if s.success() => {}
                _ => {
                    drifted.push(format!("  {path}: could not be fetched from {url}"));
                    continue;
                }
            }
        }
        let bytes = std::fs::read(&dest)?;
        let got = hex(&sha2::Sha256::digest(&bytes));
        if got == *sha {
            println!("  {path}: at the pin ({})", &sha[..8]);
        } else {
            drifted.push(format!(
                "  {path}: content hash is {} , the pin is {}",
                &got[..16],
                &sha[..16]
            ));
        }
    }

    if drifted.is_empty() {
        println!("spec-sync: every source is at its pin");
        return Ok(());
    }
    for d in &drifted {
        eprintln!("{d}");
    }
    eprintln!(
        "\nThe specification is a living document with no release tags. The working\n\
         tree is at the pin, so nothing downstream has changed. Review the upstream\n\
         diff, update the pin in `xtask/src/main.rs`, and re-run the corpus\n\
         tests before moving."
    );
    bail!("{} pinned source(s) have moved", drifted.len());
}
