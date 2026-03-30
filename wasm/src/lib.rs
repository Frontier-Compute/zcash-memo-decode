use wasm_bindgen::prelude::*;

/// Decode hex-encoded Zcash memo bytes, return JSON classification.
#[wasm_bindgen]
pub fn decode_memo(hex: &str) -> String {
    let bytes = match hex_to_bytes(hex) {
        Some(b) => b,
        None => return r#"{"error":"invalid hex"}"#.to_string(),
    };

    let decoded = zcash_memo_decode::decode(&bytes);
    let fmt = zcash_memo_decode::label(&decoded);

    match decoded {
        zcash_memo_decode::MemoFormat::Text(s) => {
            serde_json::json!({"format": fmt, "text": s}).to_string()
        }
        zcash_memo_decode::MemoFormat::Attestation {
            protocol,
            event_type,
            event_label,
            payload_hash,
            raw,
        } => serde_json::json!({
            "format": fmt,
            "protocol": match protocol {
                zcash_memo_decode::AttestationProtocol::Zap1 => "ZAP1",
                zcash_memo_decode::AttestationProtocol::Nsm1Legacy => "NSM1",
            },
            "event_type": format!("0x{:02x}", event_type),
            "event_label": event_label,
            "payload_hash": hex_encode(&payload_hash),
            "raw": raw,
        })
        .to_string(),
        zcash_memo_decode::MemoFormat::Zip302Tvlv { parts } => {
            let parts_json: Vec<serde_json::Value> = parts
                .iter()
                .map(|p| {
                    serde_json::json!({
                        "part_type": p.part_type,
                        "version": p.version,
                        "value_hex": hex_encode(&p.value),
                    })
                })
                .collect();
            serde_json::json!({"format": fmt, "parts": parts_json}).to_string()
        }
        zcash_memo_decode::MemoFormat::Empty => {
            serde_json::json!({"format": fmt}).to_string()
        }
        zcash_memo_decode::MemoFormat::Binary(data) => {
            serde_json::json!({"format": fmt, "length": data.len()}).to_string()
        }
        zcash_memo_decode::MemoFormat::Unknown {
            first_byte,
            length,
        } => serde_json::json!({
            "format": fmt,
            "first_byte": format!("0x{:02x}", first_byte),
            "length": length,
        })
        .to_string(),
    }
}

/// Encode TVLV parts from JSON array, return hex.
#[wasm_bindgen]
pub fn encode_tvlv(json: &str) -> String {
    let parts: Vec<(u16, u8, Vec<u8>)> = match serde_json::from_str(json) {
        Ok(p) => p,
        Err(e) => return format!("{{\"error\":\"{}\"}}", e),
    };
    let refs: Vec<(u16, u8, &[u8])> = parts.iter().map(|(t, v, d)| (*t, *v, d.as_slice())).collect();
    let encoded = zcash_memo_decode::encode_tvlv(&refs);
    hex_encode(&encoded)
}

fn hex_to_bytes(hex: &str) -> Option<Vec<u8>> {
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
