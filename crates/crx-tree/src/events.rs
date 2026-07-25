//! Event ABI: topic-0 selectors, per-log decoders, the Terms identity check.

use alloy::primitives::{b256, Address, B256};
use alloy::rpc::types::Log;
use alloy::sol;
use alloy::sol_types::{SolCall, SolEvent};
use tiny_keccak::{Hasher, Keccak};

pub fn keccak256(parts: &[&[u8]]) -> [u8; 32] {
    let mut k = Keccak::v256();
    for p in parts {
        k.update(p);
    }
    let mut out = [0u8; 32];
    k.finalize(&mut out);
    out
}

fn topic0(sig: &str) -> B256 {
    B256::from(keccak256(&[sig.as_bytes()]))
}

// 16-field Terms; field order is hash-affecting. `side` = partyA polarity (+1/−1), `expiry` uint40.
sol! {
    struct OpenLockTerms {
        address partyA;
        address partyB;
        address oracle;
        bytes32 pairTag;
        uint256 quantity;
        uint16  imBpsA;
        uint16  imBpsB;
        uint16  mmPct;
        uint40  expiry;
        uint64  nonce;
        uint64  cureWindow;
        uint8   payoutPrefA;
        uint8   payoutPrefB;
        bytes   data;
        uint8   instrument;
        int8    side;
    }

    function openLock(OpenLockTerms t, bytes sigA, bytes sigB);
    event TermsOpened(bytes32 indexed id, OpenLockTerms terms);
    event TwapBound(bytes32 indexed feedId, uint64 indexed closeTime, int64 twap, int32 expo);
    event MarketSet(uint8 indexed instrument, bytes32 indexed pairTag, bool enabled, bool paused, uint8 volGroup, uint8 concCat);
}

/// MIRROR of the on-chain `Rfq.TYPEHASH`; welded by the test below.
pub const TERMS_TYPEHASH: B256 =
    b256!("0x41aa73c5b957e9b7ac0f62e276c3d71b35cfec660f61675e6fb16835e3465fe4");

#[cfg(test)]
const TERMS_TYPE_STRING: &str = "Terms(address partyA,address partyB,address oracle,bytes32 pairTag,uint256 quantity,uint16 imBpsA,uint16 imBpsB,uint16 mmPct,uint40 expiry,uint64 nonce,uint64 cureWindow,uint8 payoutPrefA,uint8 payoutPrefB,bytes data,uint8 instrument,int8 side)";

fn addr_word(a: Address) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(a.as_slice());
    w
}

fn u64_word(v: u64) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&v.to_be_bytes());
    w
}

/// Recompute `Rfq.id(t)` — the EIP-712 struct hash. Must equal the `TermsOpened` id or the caller refuses.
pub fn terms_rfq_id(t: &OpenLockTerms) -> [u8; 32] {
    let mut buf = Vec::with_capacity(17 * 32);
    buf.extend_from_slice(TERMS_TYPEHASH.as_slice());
    buf.extend_from_slice(&addr_word(t.partyA));
    buf.extend_from_slice(&addr_word(t.partyB));
    buf.extend_from_slice(&addr_word(t.oracle));
    buf.extend_from_slice(t.pairTag.as_slice());
    buf.extend_from_slice(&t.quantity.to_be_bytes::<32>());
    buf.extend_from_slice(&u64_word(u64::from(t.imBpsA)));
    buf.extend_from_slice(&u64_word(u64::from(t.imBpsB)));
    buf.extend_from_slice(&u64_word(u64::from(t.mmPct)));
    buf.extend_from_slice(&u64_word(u64::try_from(t.expiry).unwrap_or(0)));
    buf.extend_from_slice(&u64_word(t.nonce));
    buf.extend_from_slice(&u64_word(t.cureWindow));
    buf.extend_from_slice(&u64_word(u64::from(t.payoutPrefA)));
    buf.extend_from_slice(&u64_word(u64::from(t.payoutPrefB)));
    buf.extend_from_slice(&keccak256(&[t.data.as_ref()]));
    let mut instr_word = [0u8; 32];
    instr_word[31] = t.instrument;
    buf.extend_from_slice(&instr_word);
    // `side` sign-extended, as `abi.encode(int8)` does.
    let mut side_word = [if t.side < 0 { 0xff } else { 0x00 }; 32];
    side_word[31] = t.side as u8;
    buf.extend_from_slice(&side_word);
    keccak256(&[&buf])
}

/// Decode Terms + both sigs from `openLock` calldata; the selector check makes this succeed only for a genuine `openLock`.
pub fn terms_from_open_calldata(calldata: &[u8]) -> Option<(OpenLockTerms, Vec<u8>, Vec<u8>)> {
    openLockCall::abi_decode(calldata)
        .ok()
        .map(|c| (c.t, c.sigA.to_vec(), c.sigB.to_vec()))
}

pub fn terms_from_opened_log(log: &Log) -> Option<([u8; 32], OpenLockTerms)> {
    let ev = TermsOpened::decode_log(&log.inner).ok()?;
    Some((ev.id.0, ev.data.terms))
}

pub struct Topics {
    pub bound: B256,
    pub terms_opened: B256,
    pub root_advanced: B256,
    pub twap_bound: B256,
    pub market_set: B256,
}

impl Topics {
    pub fn new() -> Self {
        Self {
            bound: topic0("Bound(bytes32,address,address,uint256)"),
            terms_opened: TermsOpened::SIGNATURE_HASH,
            root_advanced: topic0("RootAdvanced(bytes32,bytes32)"),
            twap_bound: TwapBound::SIGNATURE_HASH,
            market_set: MarketSet::SIGNATURE_HASH,
        }
    }

    pub fn as_filter_topics(&self) -> Vec<B256> {
        vec![self.bound, self.terms_opened, self.root_advanced, self.twap_bound, self.market_set]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terms_typehash_matches_the_signature_string() {
        assert_eq!(TERMS_TYPEHASH, topic0(TERMS_TYPE_STRING));
    }
}
