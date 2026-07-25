//! F2 bilateral unwind — tear up a LIVE position at a price BOTH parties signed. Mirrors the novation crypto
//! (`handoff::transfer_as_close`) but routes the settlement through the EXPIRY path (`resolve_account`), NOT the
//! handoff move: no incoming party, no new leaf — the leg is retired from `positions_root` and the loser→winner
//! residual settles at the till. Both A and B sign the SAME `Closeout` digest; the two recovered signers must be the
//! position's two seats, order-independent. `state_transition` binds the domain to the pinned deployment separator,
//! so a signature minted under another deployment cannot be replayed. The close price rides the signed digest, so no
//! oracle can substitute it. Per seat, the realized VM is derived from THAT seat's own `side` — the loser pays.

use crate::signed_price;
use crate::{closeout_struct_hash, eip712_digest, position_vm, PositionRecord, PositionSettlement, Unwind,
    UnwindWitness};

/// Validate a bilateral unwind's dual-sig consent and build its committed [`Unwind`] entry.
///
/// Fail-closed: recovers BOTH `Closeout` signatures and requires them to be exactly the two seats (`party_a`,
/// `party_b`) in EITHER order; a wrong or missing signer PANICS (aborts the proof). `a_position` must face
/// `party_b` — A's seat's counterparty IS B. `signed_price::recover_eth_signer` already fail-closes on a high-S or
/// out-of-range recovery id, so a malleable twin cannot pass.
pub fn unwind_close(w: &UnwindWitness) -> Unwind {
    let a_position = &w.a_position;
    let old_id = a_position.terms_id;

    assert_eq!(
        a_position.counterparty, w.party_b,
        "unwind: a_position.counterparty != party_b — A's seat must face B (forged counterparty)"
    );

    let struct_hash = closeout_struct_hash(&old_id, w.close_price, w.nonce, w.deadline);
    let digest = eip712_digest(&w.domain_separator, &struct_hash);
    let signer_a = signed_price::recover_eth_signer(&digest, &w.sig_a);
    let signer_b = signed_price::recover_eth_signer(&digest, &w.sig_b);
    let both_signed = (signer_a == w.party_a && signer_b == w.party_b)
        || (signer_a == w.party_b && signer_b == w.party_a);
    assert!(
        both_signed,
        "unwind: the two Closeout signatures do not recover BOTH parties (A and B), order-independent — \
         forged or missing bilateral consent (price/nonce/deadline/domain)"
    );

    Unwind {
        old_id,
        party_a: w.party_a,
        party_b: w.party_b,
        close_price: w.close_price,
        nonce: w.nonce,
        deadline: w.deadline,
    }
}

/// Does committed `entry` arise from a sound `unwind_close` over the witness? (Crypto failures still PANIC.)
pub fn unwind_entry_valid(w: &UnwindWitness, committed: &Unwind) -> bool {
    unwind_close(w) == *committed
}

/// The per-seat [`PositionSettlement`]s a set of validated unwinds realizes over ONE account's book: for every held
/// position whose `terms_id` is being torn up, the seat's realized VM at the signed `close_price`, from THAT seat's
/// own `side` (loser pays, winner receives). `resolve_account` then retires the leaf and emits the residual once
/// from the loser's seat. `openLock` mirrors each trade into two records sharing a `terms_id`, so BOTH the A seat
/// and the B seat inject symmetrically — each from its own book.
pub fn unwind_settlements_for_account(positions: &[PositionRecord], unwinds: &[Unwind]) -> Vec<PositionSettlement> {
    let mut out: Vec<PositionSettlement> = Vec::new();
    for p in positions {
        if let Some(u) = unwinds.iter().find(|u| u.old_id == p.terms_id) {
            out.push(PositionSettlement {
                terms_id: p.terms_id,
                vm_realized: position_vm(p.entry_rate, u.close_price, p.notional, p.side),
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use crate::test_util::*;
    use crate::*;

    #[test]
    fn unwind_close_dual_sig_happy_path_reproduces_entry() {
        let a_position = PositionRecord { side: 1, ..reference_box0() };
        let w = unwind_valid_witness(a_position, 900_000);
        let entry = unwind_close(&w);
        assert_eq!(entry.old_id, a_position.terms_id, "the torn-up id is A's position id");
        assert_eq!(entry.party_a, new_party_a(), "party A recovers from one Closeout sig");
        assert_eq!(entry.party_b, new_party_b(), "party B recovers from the other Closeout sig");
        assert_eq!(entry.close_price, 900_000, "the mutually-signed close price is surfaced");
        assert_eq!(entry.nonce, 7);
        assert_eq!(entry.deadline, 1_700_001_000);
        assert!(unwind_entry_valid(&w, &entry), "the honest entry re-derives");
    }

    #[test]
    fn unwind_close_is_signature_order_independent() {
        let a_position = PositionRecord { side: 1, ..reference_box0() };
        let mut w = unwind_valid_witness(a_position, 900_000);
        // Swap the two 65-byte signatures: A's sig in slot B and vice versa — must STILL validate both parties.
        std::mem::swap(&mut w.sig_a, &mut w.sig_b);
        let entry = unwind_close(&w);
        assert_eq!(entry.party_a, new_party_a(), "order-independent recovery still binds A");
        assert_eq!(entry.party_b, new_party_b(), "order-independent recovery still binds B");
    }

    #[test]
    #[should_panic(expected = "do not recover BOTH parties")]
    fn unwind_close_rejects_wrong_signer() {
        use k256::ecdsa::SigningKey;
        let a_position = PositionRecord { side: 1, ..reference_box0() };
        let mut w = unwind_valid_witness(a_position, 900_000);
        // Re-sign B's slot with a stranger key — B's consent is now missing.
        let stranger = SigningKey::from_bytes(&[0x44u8; 32].into()).unwrap();
        w.sig_b = unwind_sign(&stranger, &w.domain_separator, &w.a_position.terms_id, w.close_price, w.nonce, w.deadline);
        let _ = unwind_close(&w);
    }

    #[test]
    #[should_panic(expected = "a_position.counterparty != party_b")]
    fn unwind_close_rejects_counterparty_mismatch() {
        let a_position = PositionRecord { side: 1, counterparty: [0x99u8; 20], ..reference_box0() };
        // Build a witness whose party_b disagrees with a_position.counterparty.
        let mut w = unwind_valid_witness(a_position, 900_000);
        w.a_position.counterparty = [0x99u8; 20];
        let _ = unwind_close(&w);
    }

    #[test]
    fn unwind_close_binds_the_close_price_into_the_digest() {
        let a_position = PositionRecord { side: 1, ..reference_box0() };
        let w = unwind_valid_witness(a_position, 900_000);
        // A committed entry claiming a DIFFERENT close price cannot re-derive from the signed witness.
        let forged = Unwind { close_price: 950_000, ..unwind_close(&w) };
        assert!(!unwind_entry_valid(&w, &forged), "a substituted close price breaks the dual-sig binding");
    }

    #[test]
    fn unwind_settlements_are_per_seat_loser_pays() {
        // A long, B short on the same position; a below-entry close makes A the loser and B the winner.
        let entry_rate = 1_000_000u128;
        let notional = 100_000_000u128;
        let close = 900_000u128;
        let a_seat = PositionRecord { terms_id: [0x01u8; 32], entry_rate, notional, side: 1, ..reference_box0() };
        let b_seat = PositionRecord { side: -1, ..a_seat };
        let unwinds = vec![Unwind {
            old_id: [0x01u8; 32], party_a: new_party_a(), party_b: new_party_b(),
            close_price: close, nonce: 7, deadline: 1_700_001_000,
        }];

        let a_settles = unwind_settlements_for_account(&[a_seat], &unwinds);
        let b_settles = unwind_settlements_for_account(&[b_seat], &unwinds);
        assert_eq!(a_settles.len(), 1, "A's seat injects one settlement");
        assert_eq!(b_settles.len(), 1, "B's seat injects one settlement");
        let vm_a = position_vm(entry_rate, close, notional, 1);
        let vm_b = position_vm(entry_rate, close, notional, -1);
        assert!(vm_a < 0, "the long A loses on a below-entry close");
        assert!(vm_b > 0, "the short B gains symmetrically");
        assert_eq!(a_settles[0].vm_realized, vm_a, "A's realized VM is from A's OWN side");
        assert_eq!(b_settles[0].vm_realized, vm_b, "B's realized VM is from B's OWN side");
        assert_eq!(a_settles[0].vm_realized, -b_settles[0].vm_realized, "the two seats are symmetric");
    }

    #[test]
    fn unwind_settlements_ignore_untouched_positions() {
        let held = PositionRecord { terms_id: [0x01u8; 32], ..reference_box0() };
        let other = PositionRecord { terms_id: [0x02u8; 32], ..reference_box1() };
        let unwinds = vec![Unwind {
            old_id: [0x01u8; 32], party_a: new_party_a(), party_b: new_party_b(),
            close_price: 900_000, nonce: 7, deadline: 1_700_001_000,
        }];
        let settles = unwind_settlements_for_account(&[held, other], &unwinds);
        assert_eq!(settles.len(), 1, "only the torn-up position injects a settlement");
        assert_eq!(settles[0].terms_id, [0x01u8; 32], "the untouched position is left live");
    }
}
