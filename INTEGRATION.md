# Wallet Integration Guide

How to integrate `zcash-memo-decode` into a Zcash wallet or explorer.

## Add the dependency

```toml
[dependencies]
zcash-memo-decode = "0.1"
```

Zero transitive dependencies. Compiles to native and WASM.

## After trial decryption

After `zcash_client_backend::decrypt_transaction` returns decrypted outputs, each output has a memo field. Feed those bytes to the decoder:

```rust
for output in decrypted.orchard_outputs() {
    let memo_bytes = output.memo().as_array();
    let decoded = zcash_memo_decode::decode(memo_bytes);

    match decoded {
        zcash_memo_decode::MemoFormat::Text(s) => {
            // display as transaction note
        }
        zcash_memo_decode::MemoFormat::Attestation { event_label, payload_hash, .. } => {
            // show attestation badge: "PROGRAM_ENTRY verified"
            // link to verifier: frontiercompute.io/verify.html
        }
        zcash_memo_decode::MemoFormat::Zip302Tvlv { parts } => {
            // parse structured memo parts per ZIP 302 conventions
            for part in parts {
                match part.part_type {
                    160 => { /* UTF-8 text */ }
                    255 => { /* unconstrained binary */ }
                    _ => { /* application-specific */ }
                }
            }
        }
        zcash_memo_decode::MemoFormat::Empty => {
            // no memo content
        }
        zcash_memo_decode::MemoFormat::Binary(data) => {
            // show as hex or "binary data ({len} bytes)"
        }
        zcash_memo_decode::MemoFormat::Unknown { first_byte, .. } => {
            // show as "unrecognized memo format (0x{first_byte:02x})"
        }
    }
}
```

## Compatible wallets

The crate works with any wallet that uses `zcash_client_backend` for trial decryption:

- Zallet (ZODL)
- Zkool (hhanh00)
- ZingoPC (ZingoLabs)
- Any custom wallet using librustzcash

## Memo format summary

| First byte | Format | Decoder output |
|---|---|---|
| 0x00-0xF4 | UTF-8 text | `MemoFormat::Text(String)` |
| ZAP1:... | ZAP1 attestation | `MemoFormat::Attestation { event_type, payload_hash, ... }` |
| NSM1:... | Legacy attestation | `MemoFormat::Attestation { protocol: Nsm1Legacy, ... }` |
| 0xF6 | Empty | `MemoFormat::Empty` |
| 0xF7 | ZIP 302 TVLV | `MemoFormat::Zip302Tvlv { parts }` |
| 0xFF | Binary | `MemoFormat::Binary(Vec<u8>)` |

## WASM

The crate has no dependencies and uses only `core` + `alloc`. It compiles to WASM for browser-based explorers and light wallets.

## API

For applications that don't import the crate, the ZAP1 reference server exposes a REST endpoint:

```
POST https://pay.frontiercompute.io/memo/decode
Body: hex-encoded memo bytes
Response: JSON with format, parsed content
```

Browser tool: https://frontiercompute.io/memo.html

## Source

https://github.com/Frontier-Compute/zcash-memo-decode

MIT license. Zero dependencies. 23 tests.
