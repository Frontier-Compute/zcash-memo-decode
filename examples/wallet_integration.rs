//! Example: how a Zcash wallet integrates zcash-memo-decode.
//!
//! After trial decryption with zcash_client_backend::decrypt_transaction,
//! the wallet gets DecryptedOutput objects. Each has a memo field (512 bytes
//! pre-ZIP 231, up to 16 KiB post-ZIP 231).
//!
//! Feed those bytes to zcash_memo_decode::decode() and get back a typed
//! classification. No additional dependencies. No server calls.
//!
//! Works with Zallet, Zkool, ZingoPC, or any wallet using librustzcash.

fn main() {
    // simulate a memo from a decrypted Orchard output
    let mut memo_bytes = [0u8; 512];

    // example 1: plain text payment note
    let text = b"March hosting payment - Z15P-2026-001";
    memo_bytes[..text.len()].copy_from_slice(text);
    let decoded = zcash_memo_decode::decode(&memo_bytes);
    println!("1. {}: {:?}", zcash_memo_decode::label(&decoded), decoded);

    // example 2: ZAP1 attestation
    memo_bytes = [0u8; 512];
    let attestation = b"ZAP1:01:075b00df286038a7b3f6bb70054df61343e3481fba579591354a00214e9e019b";
    memo_bytes[..attestation.len()].copy_from_slice(attestation);
    let decoded = zcash_memo_decode::decode(&memo_bytes);
    println!("2. {}: {:?}", zcash_memo_decode::label(&decoded), decoded);

    // example 3: empty memo
    memo_bytes = [0u8; 512];
    memo_bytes[0] = 0xF6;
    let decoded = zcash_memo_decode::decode(&memo_bytes);
    println!("3. {}", zcash_memo_decode::label(&decoded));

    // example 4: ZIP 302 TVLV structured memo
    let tvlv = zcash_memo_decode::encode_tvlv(&[(160, 0, b"invoice #4821")]);
    let decoded = zcash_memo_decode::decode(&tvlv);
    println!("4. {}: {:?}", zcash_memo_decode::label(&decoded), decoded);

    // the wallet can switch on the format to decide how to display:
    // - Text: show in transaction detail
    // - Attestation: show event type badge + link to verifier
    // - Zip302Tvlv: parse parts and render per part type
    // - Empty: show nothing
    // - Binary/Unknown: show hex or "unrecognized memo format"
}
