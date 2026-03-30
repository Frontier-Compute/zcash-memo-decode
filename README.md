# zcash-memo-decode

Universal decoder for Zcash shielded memo formats. Feed it decrypted memo bytes, get back a typed classification.

Zero dependencies. Pure Rust. Wallet-importable.

## Supported formats

| First byte | Format | Status |
|---|---|---|
| 0x00-0xF4 | UTF-8 text | Parsed, trailing zeros trimmed |
| 0xF5 | Legacy binary agreement | Classified as unknown |
| 0xF6 | Empty memo | Detected |
| 0xF7 | ZIP 302 TVLV structured memo | Parsed into typed parts |
| 0xF8-0xFE | Reserved | Classified as unknown |
| 0xFF | Arbitrary binary | Extracted |

Within the text range, the decoder identifies:
- `ZAP1:{type}:{hash}` attestation events (Zcash Attestation Protocol v1)
- `NSM1:{type}:{hash}` legacy attestation events (pre-rename)
- Plain text (everything else)

## Usage

```rust
use zcash_memo_decode::{decode, label, MemoFormat};

let mut memo_bytes = [0u8; 512];
memo_bytes[..11].copy_from_slice(b"hello zcash");

match decode(&memo_bytes) {
    MemoFormat::Text(s) => println!("text: {s}"),
    MemoFormat::Attestation { event_label, .. } => println!("attestation: {event_label}"),
    MemoFormat::Zip302Tvlv { parts } => println!("{} TVLV parts", parts.len()),
    MemoFormat::Empty => println!("empty"),
    MemoFormat::Binary(data) => println!("{} bytes", data.len()),
    MemoFormat::Unknown { first_byte, .. } => println!("unknown: 0x{first_byte:02x}"),
}
```

## ZIP 302 TVLV

Standalone encoder/decoder for the structured memo container from ZIP 302 (draft PR #638).

```rust
use zcash_memo_decode::{encode_tvlv, decode_tvlv};

let encoded = encode_tvlv(&[(160, 0, b"hello")]);
let parts = decode_tvlv(&encoded).unwrap();
assert_eq!(parts[0].part_type, 160);
assert_eq!(parts[0].value, b"hello");
```

## Design

- Input: raw decrypted memo bytes from Orchard or Sapling outputs
- Output: typed enum with parsed content
- Unknown formats are first-class results, not errors
- No network calls. No server dependency. No async.
- Works with any memo size (512-byte pre-ZIP 231, 16 KiB post-ZIP 231)

## License

MIT
