//! secp256k1 ECDSA recover-and-verify for the position-bind path.
//!
//! Fail-closed: a wrong length, bad scalars, an out-of-range recovery id, a recovery yielding no key, or a
//! high-S signature (its twin `(r, n−s)` recovers the same signer, so it is malleable) all PANIC, which aborts
//! the proof — no forged signature survives. `v` is accepted as Ethereum `{27,28}` or raw `{0,1}`.

use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
#[allow(unused_imports)]
use k256::elliptic_curve::sec1::ToEncodedPoint;
use tiny_keccak::{Hasher, Keccak};

fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut k = Keccak::v256();
    k.update(data);
    let mut out = [0u8; 32];
    k.finalize(&mut out);
    out
}

/// The 20-byte Ethereum address of an uncompressed SEC1 public key: `keccak256(pubkey[1..])[12..]`.
fn pubkey_to_eth_addr(pubkey: &[u8]) -> [u8; 20] {
    let hash = keccak256(&pubkey[1..]);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..]);
    addr
}

/// Recover the 20-byte Ethereum address that signed a 32-byte `digest` with a 65-byte `r‖s‖v` signature.
pub fn recover_eth_signer(digest: &[u8; 32], sig: &[u8]) -> [u8; 20] {
    assert_eq!(sig.len(), 65, "recover_eth_signer: signature must be 65 bytes (r‖s‖v)");
    let mut r_s = [0u8; 64];
    r_s.copy_from_slice(&sig[..64]);
    let v = sig[64];
    let rid_byte = if v >= 27 { v - 27 } else { v };

    let signature = Signature::from_slice(&r_s)
        .expect("recover_eth_signer: invalid r‖s bytes");
    assert!(
        signature.normalize_s().is_none(),
        "recover_eth_signer: signature s must be low-S (high-S rejected)"
    );
    let rid = RecoveryId::try_from(rid_byte)
        .expect("recover_eth_signer: recovery id must be 0 or 1");

    let vk = VerifyingKey::recover_from_prehash(digest, &signature, rid)
        .expect("recover_eth_signer: ECDSA recovery failed");

    pubkey_to_eth_addr(vk.to_encoded_point(false).as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::{signature::hazmat::PrehashSigner, SigningKey};

    fn eth_address(sk: &SigningKey) -> [u8; 20] {
        pubkey_to_eth_addr(sk.verifying_key().to_encoded_point(false).as_bytes())
    }

    #[test]
    fn recover_eth_signer_round_trip() {
        let sk = SigningKey::from_bytes(
            &[0x4c, 0x08, 0x83, 0xa6, 0x91, 0x02, 0x93, 0x7d,
              0x62, 0x31, 0x47, 0x1b, 0x5d, 0xbb, 0x62, 0x04,
              0xfe, 0x51, 0x29, 0x61, 0x70, 0x82, 0x79, 0x2a,
              0xe4, 0x68, 0xd0, 0x1a, 0x3f, 0x36, 0x23, 0x18].into(),
        )
        .unwrap();

        let digest = keccak256(b"position-bind EIP-712 digest under test");
        let (sig, rid): (Signature, RecoveryId) =
            sk.sign_prehash(&digest).expect("signing failed");

        let mut rsv = [0u8; 65];
        rsv[..64].copy_from_slice(&sig.to_bytes());
        rsv[64] = rid.to_byte();
        assert_eq!(
            recover_eth_signer(&digest, &rsv),
            eth_address(&sk),
            "raw recovery-id must recover the signer"
        );

        rsv[64] = rid.to_byte() + 27;
        assert_eq!(
            recover_eth_signer(&digest, &rsv),
            eth_address(&sk),
            "Ethereum recovery-id (+27) must recover the same signer"
        );
    }

    #[test]
    #[should_panic(expected = "must be 65 bytes")]
    fn recover_eth_signer_wrong_length_panics() {
        let digest = [0u8; 32];
        let _ = recover_eth_signer(&digest, &[0u8; 64]);
    }

    #[test]
    #[should_panic(expected = "low-S")]
    fn recover_eth_signer_rejects_high_s() {
        use k256::ecdsa::{RecoveryId, Signature, SigningKey};
        let sk = SigningKey::from_slice(&[0x11u8; 32]).unwrap();
        let digest = keccak256(b"high-s malleability test");
        let (sig, rid): (Signature, RecoveryId) = sk.sign_prehash_recoverable(&digest).unwrap();
        let r = sig.r();
        let s_high = -*sig.s();
        let sig_high = Signature::from_scalars(*r, s_high).expect("from_scalars");
        let mut rsv = [0u8; 65];
        rsv[..64].copy_from_slice(&sig_high.to_bytes());
        rsv[64] = rid.to_byte() ^ 1;
        let _ = recover_eth_signer(&digest, &rsv);
    }
}
