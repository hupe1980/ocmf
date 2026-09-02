//! `ocmf` — read, check, explain and convert Open Charge Metering Format
//! records.
//!
//! The command this tool exists for is `explain`: it prints every departure a
//! record makes from the specification, with the table each one is measured
//! against. That is the check a meter manufacturer wants before a notified body
//! runs it, and nothing else does it.

use std::collections::BTreeSet;
use std::io::Read;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
use ocmf::{Curve, Limits, Profile, PublicKey, Record, SignatureAlgorithm, session, verify, xml};

#[derive(Parser)]
#[command(
    name = "ocmf",
    version,
    about = "Open Charge Metering Format: parse, explain, verify and convert signed meter records",
    long_about = None,
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print a record's fields and every departure it makes from the
    /// specification.
    Explain {
        /// A record, or a transparency XML container. `-` reads stdin.
        input: PathBuf,
        /// How strictly to read it.
        #[arg(long, value_enum, default_value_t = ProfileArg::Interop)]
        profile: ProfileArg,
        /// Emit the machine-readable report instead of the human one.
        #[arg(long)]
        json: bool,
    },
    /// Check a record's signature.
    Verify {
        /// A record, or a transparency XML container carrying its own keys.
        input: PathBuf,
        /// The public key: hex, Base64, an `oca:` composite, or `@path`.
        #[arg(long)]
        key: Option<String>,
        /// How strictly to read the record before checking it.
        #[arg(long, value_enum, default_value_t = ProfileArg::Interop)]
        profile: ProfileArg,
        /// Emit the machine-readable report instead of the human one.
        #[arg(long)]
        json: bool,
    },
    /// Run the check-component rules over a transaction's records.
    Session {
        /// Records, in the order the station produced them, or one XML
        /// container holding all of them.
        inputs: Vec<PathBuf>,
        /// How strictly to read them.
        #[arg(long, value_enum, default_value_t = ProfileArg::Interop)]
        profile: ProfileArg,
        /// Emit the machine-readable report instead of the human one.
        #[arg(long)]
        json: bool,
    },
    /// Write records into a S.A.F.E. transparency XML container.
    ToXml {
        /// One or more records.
        inputs: Vec<PathBuf>,
        /// The public key to embed, hex or `@path`.
        #[arg(long)]
        key: Option<String>,
    },
    /// Package a record as an OCPP `SignedMeterValueType`.
    ToOcpp {
        /// A record.
        input: PathBuf,
        /// The public key to include, hex or `@path`.
        #[arg(long)]
        key: Option<String>,
    },
    /// Read an OCPP `SignedMeterValueType` back into a record.
    FromOcpp {
        /// A JSON object with `signedMeterData` and, usually, `publicKey`.
        input: PathBuf,
    },
    /// Build and sign a record, for testing a pipeline end to end.
    Sign {
        /// The private scalar, hex, or `@path`. **A test key, not a meter's.**
        #[arg(long)]
        key: String,
        /// The curve to sign on. `p192` is verify-only: `p192` 0.13 publishes
        /// no signer, and a 192-bit curve is not one to build new hardware on.
        #[arg(long, value_enum, default_value_t = SignCurve::Secp256r1)]
        curve: SignCurve,
        /// `PG` counter value.
        #[arg(long, default_value_t = 1)]
        pagination: u64,
        /// `MS`, the meter serial.
        #[arg(long, default_value = "1TEST00000001")]
        meter_serial: String,
        /// `RI`, the register.
        #[arg(long, default_value = "01-00:B1.08.00*FF")]
        obis: String,
        /// The begin reading, exact decimal.
        #[arg(long, default_value = "0.000")]
        begin: String,
        /// The end reading, exact decimal.
        #[arg(long, default_value = "1.000")]
        end: String,
    },
    /// Run a conformance suite against this implementation.
    Conformance {
        /// `conformance/suite.json`, or another implementation's copy of it.
        suite: PathBuf,
        /// Print every case, not only the failures.
        #[arg(long)]
        verbose: bool,
    },
    /// List the signature algorithms this build can check.
    Curves,
}

/// The curves this build can *sign* on.
#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
enum SignCurve {
    /// secp256r1 — the OCMF default `[OCMF Tab. 22]`.
    Secp256r1,
    /// secp384r1, hashing with SHA-256 as the table requires.
    Secp384r1,
    /// secp256k1.
    Secp256k1,
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
enum ProfileArg {
    /// The specification as written; any deviation is an error.
    Strict,
    /// Bug-for-bug with the S.A.F.E. Transparenzsoftware.
    Reference,
    /// What meters actually emit; deviations are reported, not fatal.
    Interop,
}

impl From<ProfileArg> for Profile {
    fn from(p: ProfileArg) -> Self {
        match p {
            ProfileArg::Strict => Self::Strict,
            ProfileArg::Reference => Self::Reference,
            ProfileArg::Interop => Self::Interop,
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Explain {
            input,
            profile,
            json,
        } => explain(&input, profile.into(), json),
        Command::Verify {
            input,
            key,
            profile,
            json,
        } => verify_cmd(&input, key.as_deref(), profile.into(), json),
        Command::Session {
            inputs,
            profile,
            json,
        } => session_cmd(&inputs, profile.into(), json),
        Command::ToXml { inputs, key } => to_xml(&inputs, key.as_deref()),
        Command::ToOcpp { input, key } => to_ocpp(&input, key.as_deref()),
        Command::FromOcpp { input } => from_ocpp(&input),
        Command::Sign {
            key,
            curve,
            pagination,
            meter_serial,
            obis,
            begin,
            end,
        } => sign_cmd(&key, curve, pagination, &meter_serial, &obis, &begin, &end),
        Command::Conformance { suite, verbose } => conformance(&suite, verbose),
        Command::Curves => {
            println!("Signature algorithms [OCMF Tab. 22] this build can check:\n");
            let supported = verify::supported_curves();
            for c in Curve::ALL {
                let mark = if supported.contains(&c) { "yes" } else { "NO " };
                println!("  {mark}  {:<28} {}", c.algorithm().as_str(), c.name());
            }
            if supported.len() < Curve::ALL.len() {
                println!(
                    "\nThe missing curves have no pure-Rust implementation on a stable\n\
                     release. Build with `--features backend-openssl` for all seven."
                );
            }
            Ok(())
        }
    }
}

/// A record and, when the source carried one, its key.
struct Loaded {
    text: String,
    key: Option<String>,
    label: String,
}

fn read_input(path: &PathBuf) -> Result<String> {
    if path.as_os_str() == "-" {
        let mut s = String::new();
        std::io::stdin().read_to_string(&mut s)?;
        return Ok(s);
    }
    std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))
}

/// Reads either a bare record or a transparency container.
fn load(path: &PathBuf) -> Result<Vec<Loaded>> {
    let text = read_input(path)?;
    // A byte-order mark is a property of the *file*, not of the record: the
    // parser's rule is that a record starts with `OCMF` after whitespace, and
    // U+FEFF is not whitespace. Strip it once, here, where files come from.
    let text = text.strip_prefix('\u{feff}').unwrap_or(&text).to_string();
    let label = path.display().to_string();
    if text.trim_start().starts_with('<') {
        let values = xml::Values::parse(&text).map_err(|e| anyhow::anyhow!("{e}"))?;
        let mut loaded = Vec::new();
        for (i, e) in values.entries.into_iter().enumerate() {
            // A transparency container is not an OCMF file: 13 of the 247
            // values S.A.F.E. ships are SML or ISA_EDL. Saying so beats
            // reporting a missing OCMF header about a record that never
            // claimed to be one — and beats failing the whole file.
            if !e.is_ocmf() {
                eprintln!(
                    "{label}[{i}]: skipped — format `{}`, encoding `{}`, which is not OCMF",
                    e.format, e.encoding
                );
                continue;
            }
            loaded.push(Loaded {
                text: e.signed_data,
                key: e.public_key,
                label: format!("{label}[{i}]"),
            });
        }
        if loaded.is_empty() {
            bail!("{label} holds no OCMF record");
        }
        return Ok(loaded);
    }
    // A plain file holds one record per line: that is how a station's log, a
    // `grep` of one, and every export this tool writes are shaped. Blank lines
    // and `#` comments are skipped so a file can be annotated.
    //
    // A record in a file almost always has a trailing newline. The parser keeps
    // it (leading and trailing whitespace is not part of any section, and
    // `Record::to_string` must reproduce its input), but packaging it into an
    // OCPP `signedMeterData` or an XML `<signedData>` would ship the file's
    // formatting as part of the record. Trim once, here, where the file ends.
    let records: Vec<Loaded> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .enumerate()
        .map(|(i, line)| Loaded {
            text: line.to_string(),
            key: None,
            label: if i == 0 {
                label.clone()
            } else {
                format!("{label}:{}", i + 1)
            },
        })
        .collect();
    if records.is_empty() {
        bail!("{label} holds no OCMF record");
    }
    Ok(records)
}

fn key_argument(arg: &str) -> Result<String> {
    if let Some(path) = arg.strip_prefix('@') {
        return Ok(std::fs::read_to_string(path)
            .with_context(|| format!("reading key from {path}"))?
            .trim()
            .to_string());
    }
    Ok(arg.to_string())
}

fn explain(path: &PathBuf, profile: Profile, as_json: bool) -> Result<()> {
    if as_json {
        let mut summaries = Vec::new();
        for item in load(path)? {
            let record = Record::parse_with(&item.text, profile, &Limits::DEFAULT)
                .map_err(|e| anyhow::anyhow!("{}: {e}", item.label))?;
            summaries.push(record.summary());
        }
        println!("{}", serde_json::to_string_pretty(&summaries)?);
        return Ok(());
    }
    let mut breaches = 0usize;
    for item in load(path)? {
        let record = match Record::parse_with(&item.text, profile, &Limits::DEFAULT) {
            Ok(r) => r,
            Err(e) => {
                println!("{}: NOT READ — {e}", item.label);
                bail!("the record could not be read under the {profile:?} profile");
            }
        };
        let p = record.payload();
        let or = |v: Option<&str>| v.unwrap_or("-").to_string();

        println!("{}", item.label);
        row("format version", or(p.format_version()));
        row(
            "gateway",
            format!(
                "{} / {} / {}",
                or(p.gateway_id()),
                or(p.gateway_serial()),
                or(p.gateway_version())
            ),
        );
        row(
            "meter",
            format!(
                "{} {} serial {} fw {}",
                or(p.meter_vendor()),
                or(p.meter_model()),
                p.meter_serial().unwrap_or("(absent)"),
                or(p.meter_firmware())
            ),
        );
        row(
            "pagination",
            p.pagination()
                .map_or_else(|| "(unreadable)".to_string(), |v| v.to_string()),
        );
        if let Some(cf) = p.charge_controller_firmware() {
            row("controller fw", cf.to_string());
        }
        if let Some(kind) = p.charge_point_id_type() {
            row(
                "charge point",
                format!("{kind} {}", or(p.charge_point_id())),
            );
        }
        if let Some(assigned) = p.identification_status() {
            let flags: Vec<&str> = p
                .identification_flags()
                .unwrap_or(&[])
                .iter()
                .map(ocmf::IdentificationFlag::as_str)
                .collect();
            row(
                "user",
                format!(
                    "assigned={assigned} level={} type={} id={}{}",
                    p.identification_level()
                        .map_or_else(|| "-".to_string(), |l| l.to_string()),
                    p.identification_type()
                        .map_or_else(|| "-".to_string(), |t| t.to_string()),
                    or(p.identification_data()),
                    if flags.is_empty() {
                        String::new()
                    } else {
                        format!(" [{}]", flags.join(" "))
                    },
                ),
            );
        }
        if let Some(tt) = p.tariff_text() {
            row("tariff", format!("{tt:?}"));
        }
        if let Some(lc) = p.loss_compensation() {
            row(
                "cable loss",
                format!(
                    "{} {}{}",
                    lc.resistance
                        .as_ref()
                        .map_or_else(|| "(absent)".to_string(), |n| n.as_str().to_string()),
                    lc.unit
                        .map_or_else(|| "(absent)".to_string(), |u| u.to_string()),
                    lc.name
                        .as_deref()
                        .map_or_else(String::new, |n| format!(" ({n})")),
                ),
            );
        }
        row(
            "algorithm",
            format!(
                "{}{}",
                record
                    .signature()
                    .algorithm()
                    .map_or("(not in Tab. 22)", SignatureAlgorithm::as_str),
                if record.signature().algorithm_was_written() {
                    ""
                } else {
                    "  (defaulted; SA absent)"
                }
            ),
        );
        row("payload bytes", record.signed_bytes().len().to_string());
        if let Some(key) = record.embedded_public_key() {
            row(
                "embedded key",
                format!("{} bytes (withdrawn fourth section)", key.len()),
            );
        }

        // One line per reading, saying what it wrote rather than what it means:
        // a record whose readings inherit from one another cannot be read a
        // reading at a time, and that is worth seeing.
        row("readings", p.readings().len().to_string());
        for (i, r) in p.readings().iter().enumerate() {
            let wrote: Vec<&str> = r.explicit().fields().collect();
            println!(
                "    [{i}] {:<30} {:>12} {:<4} {:<20} {}{}",
                r.time()
                    .map_or_else(|| "(no TM)".to_string(), |t| t.to_string()),
                r.value()
                    .map_or_else(|| "-".to_string(), |v| v.as_str().to_string()),
                r.unit().map_or_else(|| "-".to_string(), |u| u.to_string()),
                r.obis()
                    .map_or_else(|| "-".to_string(), |o| o.as_str().to_string()),
                if r.is_billable() {
                    "billable"
                } else {
                    "not billable"
                },
                if wrote.len() == 9 {
                    String::new()
                } else {
                    format!("  (wrote {})", wrote.join(","))
                },
            );
        }
        for series in p.by_register() {
            let unit = series
                .readings
                .first()
                .and_then(|r| r.unit())
                .map_or_else(|| "-".to_string(), |u| u.to_string());
            match series.delta() {
                Some(d) => println!("    {:<20} Δ {d} {unit}", series.obis),
                None => println!("    {:<20} (no begin/end pair)", series.obis),
            }
        }

        // Vendor extensions sit *inside the signature* and are dropped by every
        // reader that models only the specified extension points.
        let extras: Vec<String> = p
            .object()
            .extras(&ocmf::Payload::KNOWN_KEYS)
            .map(|(k, _)| k.decode().into_owned())
            .chain(p.readings().iter().enumerate().flat_map(|(i, r)| {
                r.object()
                    .extras(&ocmf::Reading::KNOWN_KEYS)
                    .map(move |(k, _)| format!("RD[{i}].{}", k.decode()))
            }))
            .collect();
        if !extras.is_empty() {
            row("extensions", extras.join(" "));
        }

        if record.deviations().is_empty() {
            row("deviations", "none".to_string());
        } else {
            let n = record.deviations().iter().filter(|d| d.is_breach()).count();
            breaches += n;
            row(
                "deviations",
                format!(
                    "{} ({n} breach the specification, {} advisory)",
                    record.deviations().len(),
                    record.deviations().len() - n
                ),
            );
            for d in record.deviations() {
                println!("    {} {d}", if d.is_breach() { "!" } else { "·" });
            }
        }
        println!();
    }
    if breaches > 0 && profile == Profile::Strict {
        bail!("the record deviates from the specification");
    }
    Ok(())
}

/// One aligned `label  value` line of the human report.
fn row(label: &str, value: String) {
    println!("  {label:<16} {value}");
}

fn resolve_key(item: &Loaded, arg: Option<&str>, record: &Record<'_>) -> Result<PublicKey> {
    let hint = record.signature().curve();
    let text = match arg {
        Some(a) => key_argument(a)?,
        None => item
            .key
            .clone()
            .context("no public key: pass --key, or use a container that carries one")?,
    };
    PublicKey::from_text(&text, hint).map_err(|e| anyhow::anyhow!("{e}"))
}

/// One record's verdict, for `--json`.
#[derive(serde::Serialize)]
struct VerifyReport {
    /// Where the record came from: the file, or `file[3]` inside a container.
    label: String,
    /// Whether the signature is authentic — and nothing else.
    verified: bool,
    /// Why not, when it is not: the error's own words, so a pipeline can tell
    /// `Unsupported` from `NotVerified` without re-deriving the distinction.
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    /// The record and everything derived from it.
    summary: ocmf::RecordSummary,
}

fn verify_cmd(path: &PathBuf, key: Option<&str>, profile: Profile, as_json: bool) -> Result<()> {
    let mut failures = 0usize;
    let mut reports = Vec::new();
    for item in load(path)? {
        let record = Record::parse_with(&item.text, profile, &Limits::DEFAULT)
            .map_err(|e| anyhow::anyhow!("{}: {e}", item.label))?;
        let public_key = resolve_key(&item, key, &record)?;
        let outcome = verify::verify(&record, &public_key);
        if outcome.is_err() {
            failures += 1;
        }
        if as_json {
            reports.push(match &outcome {
                Ok(v) => VerifyReport {
                    label: item.label.clone(),
                    verified: true,
                    error: None,
                    summary: v.summary(),
                },
                Err(e) => VerifyReport {
                    label: item.label.clone(),
                    verified: false,
                    error: Some(e.to_string()),
                    summary: record.summary(),
                },
            });
            continue;
        }
        match outcome {
            Ok(v) => {
                println!(
                    "{}: VERIFIED  {}  {} deviation(s)",
                    item.label,
                    v.algorithm(),
                    v.deviations().len()
                );
                for d in v.deviations() {
                    println!("    - {d}");
                }
            }
            Err(e) => println!("{}: NOT VERIFIED — {e}", item.label),
        }
    }
    if as_json {
        println!("{}", serde_json::to_string_pretty(&reports)?);
    }
    if failures > 0 {
        bail!("{failures} record(s) did not verify");
    }
    Ok(())
}

fn session_cmd(paths: &[PathBuf], profile: Profile, as_json: bool) -> Result<()> {
    let mut texts = Vec::new();
    for p in paths {
        for item in load(p)? {
            texts.push(item.text);
        }
    }
    let records: Vec<Record<'_>> = texts
        .iter()
        .map(|t| {
            Record::parse_with(t, profile, &Limits::DEFAULT).map_err(|e| anyhow::anyhow!("{e}"))
        })
        .collect::<Result<_>>()?;

    let report = session::validate(&records);
    if as_json {
        // Every quantity is the decimal's exact text: a JSON number goes
        // through `f64` in most consumers, and these are kilowatt-hours.
        println!("{}", serde_json::to_string_pretty(&report)?);
        return if report.is_clean() {
            Ok(())
        } else {
            bail!("the sequence does not hold together")
        };
    }
    println!(
        "{} record(s), judged as {}",
        records.len(),
        match report.kind() {
            ocmf::SequenceKind::Transaction => "a transaction",
            // `[OCMF Tab. 2]`: fiscal readings are independent of
            // transactions, so the marker rules do not apply to them.
            _ => "fiscal readings (no transaction markers expected)",
        }
    );
    for t in report.totals() {
        println!(
            "  {:<20} {} → {}  Δ {} {}",
            t.obis, t.begin, t.end, t.delta, t.unit
        );
    }
    if let Some(c) = report.clock() {
        println!(
            "  clock            {} (the weakest in the sequence){}",
            c.letter(),
            if c.duration_is_billable() {
                ""
            } else {
                " — not fit for a duration"
            }
        );
    }
    if report.is_clean() {
        println!("\nEvery check-component rule holds.");
        println!("(That is not a statement about billing: the key still has to be");
        println!(" bound to this charge point out of band.)");
        return Ok(());
    }
    println!("\n{} finding(s):", report.findings().len());
    for f in report.findings() {
        println!("  - {f}");
    }
    bail!("the sequence does not hold together");
}

fn to_xml(paths: &[PathBuf], key: Option<&str>) -> Result<()> {
    let mut texts = Vec::new();
    for p in paths {
        for item in load(p)? {
            texts.push(item.text);
        }
    }
    let records: Vec<Record<'_>> = texts
        .iter()
        .map(|t| Record::parse(t).map_err(|e| anyhow::anyhow!("{e}")))
        .collect::<Result<_>>()?;
    let public_key = match key {
        Some(a) => {
            let hint = records.first().and_then(|r| r.signature().curve());
            Some(
                PublicKey::from_text(&key_argument(a)?, hint)
                    .map_err(|e| anyhow::anyhow!("{e}"))?,
            )
        }
        None => None,
    };
    let values = xml::Values::from_records(records.iter().map(|r| (r, public_key.as_ref())));
    print!("{}", values.to_xml().map_err(|e| anyhow::anyhow!("{e}"))?);
    Ok(())
}

fn to_ocpp(path: &PathBuf, key: Option<&str>) -> Result<()> {
    let items = load(path)?;
    let item = items.first().context("no record in the input")?;
    let record = Record::parse(&item.text).map_err(|e| anyhow::anyhow!("{e}"))?;
    let public_key = match key {
        Some(a) => Some(
            PublicKey::from_text(&key_argument(a)?, record.signature().curve())
                .map_err(|e| anyhow::anyhow!("{e}"))?,
        ),
        None => None,
    };
    let smv = ocmf::ocpp::SignedMeterValue::from_record(&record, public_key.as_ref());
    // The JSON an OCPP message carries, serialised by the same derive a CSMS
    // would use rather than assembled by hand.
    println!("{}", serde_json::to_string_pretty(&smv)?);
    eprintln!(
        "context: {}",
        ocmf::ocpp::MeterValueContext::for_record(&record).as_str()
    );
    Ok(())
}

fn from_ocpp(path: &PathBuf) -> Result<()> {
    let text = read_input(path)?;
    let smv: ocmf::ocpp::SignedMeterValue =
        serde_json::from_str(&text).context("reading the SignedMeterValueType JSON")?;
    if !smv.encoding_method.is_empty() && smv.encoding_method != ocmf::ocpp::ENCODING_METHOD {
        eprintln!(
            "warning: encodingMethod is `{}`, not `OCMF` — reading it as OCMF anyway",
            smv.encoding_method
        );
    }
    let record_text = smv.record_text().map_err(|e| anyhow::anyhow!("{e}"))?;
    let record = Record::parse(&record_text).map_err(|e| anyhow::anyhow!("{e}"))?;
    println!("{record}");

    match smv.key(record.signature().curve()) {
        Ok(Some(key)) => match verify::verify(&record, &key) {
            Ok(v) => eprintln!(
                "VERIFIED with the key that travelled with it ({})",
                v.algorithm()
            ),
            Err(e) => bail!("the record did not verify: {e}"),
        },
        Ok(None) => eprintln!(
            "no publicKey in the message; fetch it from `MeterPublicKey[ConnectorID]` \
             or your own registry"
        ),
        Err(e) => bail!("the publicKey field is unreadable: {e}"),
    }
    Ok(())
}

fn sign_cmd(
    key: &str,
    curve: SignCurve,
    pagination: u64,
    meter_serial: &str,
    obis: &str,
    begin: &str,
    end: &str,
) -> Result<()> {
    use ocmf::sign::{
        ReadingSpec, RecordBuilder, Secp256k1Signer, Secp256r1Signer, Secp384r1Signer, Signer,
    };
    use ocmf::{IdentificationLevel, IdentificationType, Location, OcmfTime, Pagination, Unit};
    use rust_decimal::Decimal;

    let scalar = ocmf::encoding::hex_decode(&key_argument(key)?)
        .context("the private scalar must be hex")?;

    let t = |s: &str| -> Result<OcmfTime> {
        OcmfTime::parse(s, &Location::at(0), &mut Vec::new())
            .with_context(|| format!("`{s}` is not an OCMF timestamp"))
    };
    let begin_value = Decimal::from_str_exact(begin).context("--begin must be an exact decimal")?;
    let end_value = Decimal::from_str_exact(end).context("--end must be an exact decimal")?;

    let builder = RecordBuilder::new()
        .gateway("ocmf-cli", "CLI-1", env!("CARGO_PKG_VERSION"))
        .pagination(Pagination::transaction(pagination))
        .meter_serial(meter_serial)
        // `[OCMF Tab. 4]`: a transaction record says whether a user was
        // assigned, even when the answer is "nobody".
        .identification(
            false,
            IdentificationLevel::None,
            Vec::new(),
            IdentificationType::None,
            "",
        )
        .reading(
            ReadingSpec::new(
                t("2024-03-01T08:00:00,000+0100 S")?,
                begin_value,
                obis,
                Unit::KWh,
            )
            .begin(),
        )
        .reading(
            ReadingSpec::new(
                t("2024-03-01T09:30:00,000+0100 S")?,
                end_value,
                obis,
                Unit::KWh,
            )
            .end(),
        );

    // Each signer is a distinct type, so the record and the key are produced
    // inside the arm that knows the curve.
    let bad = |e: ocmf::BuildError| anyhow::anyhow!("{e}");
    let (record, public) = match curve {
        SignCurve::Secp256r1 => {
            let s = Secp256r1Signer::from_bytes(&scalar).map_err(bad)?;
            (builder.sign(&s).map_err(bad)?, s.public_key().map_err(bad)?)
        }
        SignCurve::Secp384r1 => {
            let s = Secp384r1Signer::from_bytes(&scalar).map_err(bad)?;
            (builder.sign(&s).map_err(bad)?, s.public_key().map_err(bad)?)
        }
        SignCurve::Secp256k1 => {
            let s = Secp256k1Signer::from_bytes(&scalar).map_err(bad)?;
            (builder.sign(&s).map_err(bad)?, s.public_key().map_err(bad)?)
        }
    };

    println!("{record}");
    eprintln!(
        "public key (hex SPKI): {}",
        ocmf::encoding::hex_encode_upper(&public.to_spki())
    );
    Ok(())
}

/// Runs a conformance suite — the command another implementation would port.
fn conformance(path: &PathBuf, verbose: bool) -> Result<()> {
    let raw = read_input(path)?;
    let doc: serde_json::Value = serde_json::from_str(&raw).context("reading the suite")?;
    let cases = doc
        .get("cases")
        .and_then(serde_json::Value::as_array)
        .context("the suite has no `cases` array")?;

    let (mut passed, mut skipped) = (0usize, 0usize);
    let mut failures: Vec<String> = Vec::new();

    for case in cases {
        let s = |k: &str| case.get(k).and_then(serde_json::Value::as_str);
        let id = s("id").unwrap_or("(unnamed)");
        let record_text = s("record").context("a case with no record")?;
        let expect = case.get("expect").context("a case with no expectations")?;
        let flag = |k: &str| expect.get(k).and_then(serde_json::Value::as_bool);
        let count = |k: &str| {
            expect
                .get(k)
                .and_then(serde_json::Value::as_u64)
                .and_then(|n| usize::try_from(n).ok())
        };

        let mut problems: Vec<String> = Vec::new();
        let parsed = Record::parse(record_text);
        if let Some(want) = flag("parses")
            && parsed.is_ok() != want
        {
            problems.push(format!("parses: expected {want}, got {}", parsed.is_ok()));
        }
        let mut was_skipped = false;
        if let Ok(record) = &parsed {
            if flag("round_trips") == Some(true) && record.to_string() != record_text {
                problems.push("round trip is not the identity".into());
            }
            if let Some(want) = count("readings") {
                let got = record.payload().readings().len();
                if got != want {
                    problems.push(format!("readings: expected {want}, got {got}"));
                }
            }
            if let Some(want) = count("billable_readings") {
                let got = record
                    .payload()
                    .readings()
                    .iter()
                    .filter(|r| r.is_billable())
                    .count();
                if got != want {
                    problems.push(format!("billable_readings: expected {want}, got {got}"));
                }
            }

            // Deviations are collected last, because three of them
            // (`RawSignatureNotDer`, `NonCanonicalDer`, `HighSSignature`) are
            // only discoverable while checking a signature.
            let mut observed: BTreeSet<String> = record
                .deviations()
                .iter()
                .map(|d| d.kind.name().to_string())
                .collect();

            if let (Some(want), Some(key_text)) = (flag("verifies"), s("key")) {
                let hint = record.signature().curve();
                match PublicKey::from_text(key_text, hint) {
                    Ok(key) => match verify::verify(record, &key) {
                        Err(ocmf::VerifyError::Unsupported { algorithm, .. }) => {
                            was_skipped = true;
                            if verbose {
                                println!("SKIP {id} — {algorithm} unavailable in this build");
                            }
                        }
                        result => {
                            if let Ok(v) = &result {
                                observed = v
                                    .deviations()
                                    .iter()
                                    .map(|d| d.kind.name().to_string())
                                    .collect();
                            }
                            if result.is_ok() != want {
                                problems.push(format!(
                                    "verifies: expected {want}, got {}",
                                    result.map_or_else(|e| e.to_string(), |_| "verified".into())
                                ));
                            }
                        }
                    },
                    Err(e) => problems.push(format!("the case's key does not read: {e}")),
                }
            }

            if let Some(want) = expect
                .get("deviations")
                .and_then(serde_json::Value::as_array)
            {
                let want: BTreeSet<String> = want
                    .iter()
                    .filter_map(|d| d.as_str().map(ToString::to_string))
                    .collect();
                // Equality where the case was fully checked; a subset where it
                // was skipped, because the three verification-time deviations
                // are then out of reach — the rule the suite's schema states.
                let ok = if was_skipped {
                    observed.is_subset(&want)
                } else {
                    observed == want
                };
                if !ok {
                    let missing: Vec<_> = want.difference(&observed).cloned().collect();
                    let extra: Vec<_> = observed.difference(&want).cloned().collect();
                    problems.push(format!(
                        "deviations: missing {missing:?}, unexpected {extra:?}"
                    ));
                }
            }
        }

        if was_skipped && problems.is_empty() {
            skipped += 1;
        } else if problems.is_empty() {
            passed += 1;
            if verbose {
                println!("PASS {id}");
            }
        } else {
            failures.push(format!("FAIL {id}\n       {}", problems.join("\n       ")));
        }
    }

    for f in &failures {
        println!("{f}");
    }
    println!(
        "\n{} case(s): {passed} passed, {} failed, {skipped} skipped",
        cases.len(),
        failures.len()
    );
    if !failures.is_empty() {
        bail!("{} conformance failure(s)", failures.len());
    }
    Ok(())
}
