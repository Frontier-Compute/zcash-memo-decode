//! CLI for zcash-memo-decode.
//!
//! Feed hex-encoded memo bytes, get back a typed classification.
//! Useful for wallet developers, explorers, and debugging.

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    if args.is_empty() || args[0] == "--help" || args[0] == "-h" {
        eprintln!("Usage: zcash-memo-decode <hex-encoded-memo-bytes>");
        eprintln!("       echo <hex> | zcash-memo-decode -");
        eprintln!();
        eprintln!("Examples:");
        eprintln!("  zcash-memo-decode 68656c6c6f");
        eprintln!("  echo f7fda000... | zcash-memo-decode -");
        std::process::exit(0);
    }

    let hex_input = if args[0] == "-" {
        let mut buf = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut buf).unwrap_or(0);
        buf.trim().to_string()
    } else {
        args[0].trim().to_string()
    };

    let bytes = match hex_decode(&hex_input) {
        Some(b) => b,
        None => {
            eprintln!("error: invalid hex input");
            std::process::exit(1);
        }
    };

    let decoded = zcash_memo_decode::decode(&bytes);
    let fmt = zcash_memo_decode::label(&decoded);

    println!("format: {fmt}");
    println!("length: {} bytes", bytes.len());

    match decoded {
        zcash_memo_decode::MemoFormat::Text(s) => {
            println!("text: {s}");
        }
        zcash_memo_decode::MemoFormat::Attestation {
            protocol,
            event_type,
            event_label,
            payload_hash,
            raw,
        } => {
            println!("protocol: {protocol:?}");
            println!("event_type: 0x{event_type:02x} ({event_label})");
            println!("payload_hash: {}", hex_encode(&payload_hash));
            println!("raw: {raw}");
        }
        zcash_memo_decode::MemoFormat::Zip302Tvlv { parts } => {
            println!("parts: {}", parts.len());
            for (i, p) in parts.iter().enumerate() {
                let utf8 = String::from_utf8(p.value.clone()).ok();
                println!(
                    "  [{i}] type={} version={} len={} {}",
                    p.part_type,
                    p.version,
                    p.value.len(),
                    utf8.map(|s| format!("text=\"{s}\""))
                        .unwrap_or_else(|| format!("hex={}", hex_encode(&p.value)))
                );
            }
        }
        zcash_memo_decode::MemoFormat::Empty => {}
        zcash_memo_decode::MemoFormat::Binary(data) => {
            println!("data: {} bytes", data.len());
            if data.len() <= 64 {
                println!("hex: {}", hex_encode(&data));
            }
        }
        zcash_memo_decode::MemoFormat::Unknown { first_byte, .. } => {
            println!("first_byte: 0x{first_byte:02x}");
        }
    }
}

fn hex_decode(hex: &str) -> Option<Vec<u8>> {
    let hex = hex.replace(' ', "");
    if hex.len() % 2 != 0 {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
