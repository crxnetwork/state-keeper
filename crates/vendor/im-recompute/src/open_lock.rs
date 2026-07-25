//! The `openLock` pre-pass (Core 2.0): bind a newly-`Bound` position's economics to its signed `terms_id`, size each
//! seat's flat-bps IM, and PUSH both mirrored `PositionRecord`s onto the two accounts' books. No leaf money
//! moves and there is NO affordability gate — IM coverage is enforced ON-CHAIN. Both parties are authenticated BEFORE any
//! surface, so a forged `{victim's id, expiry: past}` panics rather than reaching the expired-reject path. A party MAY be
//! a contract consenting by ERC-1271, whose signature recovers to the OWNER and not the desk: it passes an EMPTY sentinel
//! signature and DEFERS to the on-chain `opened[id]` re-assert — a mark set only by `openLock`, only after both parties
//! verified, and consumed one-shot per folded id. `terms_id` excludes the signature, so that party's PARAMS stay pinned by
//! the id anyway; empty is the ONLY sentinel, and any non-empty signature takes the full ECDSA check. `side_a` is the
//! trailing `int8 side` field of the signed Terms (2.1, F-2 close): it threads into the `terms_id` recompute, so a
//! flipped side no longer reproduces the signed id and the proof turns unsatisfiable; a polarity floor (±1 only)
//! remains as the last line of defense for a signed non-polar side. The mirror seat is `-side_a`.

use crate::signed_price;
use crate::{NewPosition, PositionRecord, Account, RiskInputs,
    market_key, terms_id, eip712_digest,
    entry_rate_from_data, assert_unique_terms_id,
    BPS_DENOM, PRICE_SCALE};

/// Gross notional `quantity × rate / PRICE_SCALE` (the IM base), in collateral minor units. Pure, saturating.
pub fn gross_notional(quantity: u128, rate: u128) -> u128 {
    quantity
        .saturating_mul(rate)
        .saturating_div(PRICE_SCALE as u128)
}

/// Assert a `Bound`/novated position's economics are the SIGNED ones — a forged field fails closed before margin.
pub fn assert_new_position_bound(nb: &NewPosition) {
    let recomputed = terms_id(
        &nb.party_a,
        &nb.party_b,
        &nb.oracle,
        &nb.pair_tag,
        nb.quantity,
        nb.im_bps_a,
        nb.im_bps_b,
        nb.mm_pct,
        nb.expiry,
        nb.nonce,
        nb.cure_window,
        nb.payout_pref_a,
        nb.payout_pref_b,
        &nb.data,
        nb.instrument,
        nb.side_a,
    );
    assert_eq!(
        recomputed, nb.terms_id,
        "new position: recomputed Rfq.id(Terms) != claimed terms_id — forged position economics"
    );

    let digest = eip712_digest(&nb.domain_separator, &nb.terms_id);
    if !nb.sig_a.is_empty() {
        assert_eq!(
            signed_price::recover_eth_signer(&digest, &nb.sig_a),
            nb.party_a,
            "new position: sigA does not recover partyA — missing/forged maker consent"
        );
    }
    if !nb.sig_b.is_empty() {
        assert_eq!(
            signed_price::recover_eth_signer(&digest, &nb.sig_b),
            nb.party_b,
            "new position: sigB does not recover partyB — missing/forged taker consent"
        );
    }

    let bound_entry = entry_rate_from_data(&nb.data)
        .expect("new position: entry-rate word exceeds u128 — unrepresentable");
    assert_eq!(
        bound_entry, nb.entry_rate,
        "new position: entry_rate != first word of signed data — fabricated entry rate"
    );

    // No static im_bps minimum: parties may sign ANY im_bps (pure scenario-ES margin). The signed
    // im_bps still sizes the seat's pushed_im, and book-level risk margin is the scenario-ES floor.

    // F-2 (side_a authenticity — CLOSED in Terms 2.1): `side_a` is the trailing `int8 side` typehash field,
    // threaded into the `terms_id` recompute above, so a flipped side no longer reproduces the signed id and the
    // proof turns unsatisfiable. The polarity floor below is retained fail-closed — a signed non-polar side (0/2)
    // would still match the recompute, so reject any non-±1 side (a non-polar side breaks matched-principal netting).
    assert!(
        nb.side_a == 1 || nb.side_a == -1,
        "new position: side_a must be exactly +1 or -1 — a non-polar side breaks matched-principal netting"
    );
}

/// One seat's IM = `ceil(gross × im_bps / 1e4)`, base = gross notional. Rounds up — never a wei short.
pub fn im_for_side(gross: u128, im_bps: u16) -> u128 {
    gross
        .saturating_mul(im_bps as u128)
        .saturating_add(BPS_DENOM - 1)
        .saturating_div(BPS_DENOM)
}

/// One party's new-position half: the seat's `PositionRecord` and its sized IM. No leaf money.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SeatLock {
    /// The new `PositionRecord` for this seat.
    pub position_record: PositionRecord,
    /// IM sized for this seat (surfaced later as an `ImRequirement`; coverage is on-chain).
    pub im: u128,
}

/// Result of sizing one position's matched-principal IM for BOTH seats.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NewPositionLock {
    /// Both seats built: A's half (side `side_a`), then B's (opposite side).
    Locked {
        /// Seat A's new-position half.
        a: SeatLock,
        /// Seat B's new-position half.
        b: SeatLock,
    },
    /// Degenerate (zero-IM) position — rejected rather than silently dropped, so its `terms_id` still surfaces.
    Rejected,
}

/// Build a position's matched-principal seats: bind the signed terms, size each seat's party-signed `im_bps`
/// IM, and mirror the two records. The ISDA √-concentration floor at open and the static `MIN_IM_BPS`
/// minimum were DELETED in the scenario-ES migration — book-level risk margin now comes from the
/// scenario-ES `imRequirements` emitted every fold; the seat lock is exactly what the parties signed.
pub fn apply_new_position(nb: &NewPosition) -> NewPositionLock {
    assert_new_position_bound(nb);

    let gross = gross_notional(nb.quantity, nb.entry_rate);
    let mk = market_key(nb.instrument, &nb.pair_tag);
    let im_a = im_for_side(gross, nb.im_bps_a);
    let im_b = im_for_side(gross, nb.im_bps_b);

    if im_a == 0 || im_b == 0 {
        return NewPositionLock::Rejected;
    }

    let position_a = PositionRecord {
        terms_id: nb.terms_id,
        counterparty: nb.party_b,
        oracle: nb.oracle,
        notional: gross,
        entry_rate: nb.entry_rate,
        side: nb.side_a,
        expiry: nb.expiry,
        pushed_im: im_a,
        market_key: mk,
    };
    let position_b = PositionRecord {
        terms_id: nb.terms_id,
        counterparty: nb.party_a,
        oracle: nb.oracle,
        notional: gross,
        entry_rate: nb.entry_rate,
        side: -nb.side_a,
        expiry: nb.expiry,
        pushed_im: im_b,
        market_key: mk,
    };

    NewPositionLock::Locked {
        a: SeatLock { position_record: position_a, im: im_a },
        b: SeatLock { position_record: position_b, im: im_b },
    }
}

/// What `apply_new_boxes_to_book` FINISHED this epoch for the single USD book.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BookOpenOutcome {
    /// `terms_id` of every new position REJECTED (degenerate / missing seat / expired) — each chains a `Rejected` event.
    pub rejected: Vec<[u8; 32]>,
    /// `terms_id` of EVERY new position FINISHED, collected at ONE point and re-asserted on-chain against a real `openLock` open mark — the phantom-box and cross-epoch replay close.
    pub opened: Vec<[u8; 32]>,
}

/// Apply the book's newly-`Bound` positions to its accounts: authenticate, surface, then push both mirrored records.
pub fn apply_new_boxes_to_book(
    accounts: &mut [(Account, RiskInputs)],
    new_positions: &[NewPosition],
    proof_time: u64,
) -> BookOpenOutcome {
    let mut rejected: Vec<[u8; 32]> = Vec::new();
    let mut opened: Vec<[u8; 32]> = Vec::new();

    for nb in new_positions {
        assert_new_position_bound(nb);
        opened.push(nb.terms_id);
        if nb.expiry <= proof_time {
            rejected.push(nb.terms_id);
            continue;
        }
        let ia = accounts.iter().position(|(a, _)| a.account_owner == nb.party_a);
        let ib = accounts.iter().position(|(a, _)| a.account_owner == nb.party_b);
        let (ia, ib) = match (ia, ib) {
            (Some(ia), Some(ib)) if ia != ib => (ia, ib),
            _ => {
                rejected.push(nb.terms_id);
                continue;
            }
        };

        match apply_new_position(nb) {
            NewPositionLock::Locked { a, b } => {
                accounts[ia].1.positions.push(a.position_record);
                accounts[ib].1.positions.push(b.position_record);
            }
            NewPositionLock::Rejected => rejected.push(nb.terms_id),
        }
    }

    for (_, ri) in accounts.iter() {
        assert_unique_terms_id(&ri.positions);
    }

    BookOpenOutcome { rejected, opened }
}

#[cfg(test)]
mod tests {
    use crate::test_util::*;
    use crate::*;

    use k256::ecdsa::SigningKey;

    #[test]
    fn new_position_im_math() {
        assert_eq!(gross_notional(1_000_000, 1_080_000), 1_080_000, "gross = quantity × rate / 1e6");
        assert_eq!(im_for_side(1_080_000, 500), 54_000, "5% IM on 1.08M gross (exact)");
        assert_eq!(im_for_side(1_080_000, 300), 32_400, "3% IM on 1.08M gross (exact)");
        assert_eq!(im_for_side(1_080_000, 0), 0, "0 bps ⇒ 0 IM");
        assert_eq!(im_for_side(1, 1), 1, "0.0001 of 1 rounds up to 1 (ceiling)");
        assert_eq!(im_for_side(1_080_001, 500), 54_001, "54_000.05 rounds up to 54_001");
        assert_eq!(im_for_side(0, 500), 0, "zero gross ⇒ zero IM (no off-by-one)");
    }

    #[test]
    fn new_position_locks_both_parties() {
        let nb = a_new_position();
        let gross = gross_notional(nb.quantity, nb.entry_rate);
        let im_a = im_for_side(gross, nb.im_bps_a);
        let im_b = im_for_side(gross, nb.im_bps_b);
        let (a, b) = match apply_new_position(&nb) {
            NewPositionLock::Locked { a, b } => (a, b),
            NewPositionLock::Rejected => panic!("both seats funded — must lock"),
        };
        assert_eq!(a.im, im_a, "A's IM = the flat bps seat lock");
        assert_eq!(a.position_record.side, 1, "A keeps the signed side");
        assert_eq!(a.position_record.counterparty, new_party_b(), "A's matched counterparty is B");
        assert_eq!(a.position_record.pushed_im, im_a, "A's position carries A's computed IM");
        assert_eq!(a.position_record.notional, gross, "position notional = gross");
        assert_eq!(b.im, im_b);
        assert_eq!(b.position_record.side, -1, "B takes the opposite side (matched principal)");
        assert_eq!(b.position_record.counterparty, new_party_a(), "B's matched counterparty is A");
        assert_eq!(b.position_record.pushed_im, im_b, "B's position carries B's computed IM");
        assert_eq!(a.position_record.terms_id, b.position_record.terms_id);
        assert_eq!(a.position_record.terms_id, nb.terms_id);
    }

    #[test]
    fn apply_new_position_rejects_degenerate_zero_im() {
        let party_a = new_party_a();
        let party_b = new_party_b();
        let oracle = [0u8; 20];
        let (quantity, entry_rate, expiry) = (0u128, 1_080_000u128, 1_700_000_000u64);
        let (mm_pct, nonce, cure_window, pair_tag) = (5_000u16, 1u64, 0u64, [0x07u8; 32]);
        let data = nb_data_for_entry(entry_rate);
        let (im_bps_a, im_bps_b) = (800u16, 900u16);
        let terms_id = terms_id(&party_a, &party_b, &oracle, &pair_tag, quantity,
            im_bps_a, im_bps_b, mm_pct, expiry, nonce, cure_window, 0, 0, &data, 1u8, 1);
        let domain_separator = nb_domain();
        let digest = eip712_digest(&domain_separator, &terms_id);
        let nb = NewPosition {
            terms_id, party_a, party_b, oracle, quantity, entry_rate, side_a: 1, expiry,
            im_bps_a, im_bps_b, instrument: 1, pair_tag, mm_pct, nonce, cure_window,
            payout_pref_a: 0, payout_pref_b: 0, data,
            sig_a: nb_sign(&nb_sk_a(), &digest), sig_b: nb_sign(&nb_sk_b(), &digest), domain_separator,
        };
        assert_eq!(gross_notional(nb.quantity, nb.entry_rate), 0, "the fixture really is zero-gross");
        assert_eq!(apply_new_position(&nb), NewPositionLock::Rejected,
            "a degenerate zero-IM position must be rejected, never locked");
    }

    #[test]
    fn new_position_bind_accepts_both_polar_sides() {
        // Terms 2.1: side is signed into the id, so each side is its OWN signed position (you cannot flip
        // side_a on a fixed id — that is exactly the forgery the bind now rejects).
        assert_new_position_bound(&signed_new_position(1));
        assert_new_position_bound(&signed_new_position(-1));
    }

    #[test]
    fn new_position_non_polar_side_panics_the_bind() {
        // A non-polar side that is genuinely SIGNED into the id (so the id-recompute passes) must still be
        // rejected by the polarity floor — the last line of defense once side is a bound field.
        for bad in [0i8, 2, -3] {
            let nb = signed_new_position(bad);
            let err = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| assert_new_position_bound(&nb)))
                .expect_err(&format!("side_a = {bad} must panic the bind"));
            let msg = err.downcast_ref::<String>().map(String::as_str)
                .or_else(|| err.downcast_ref::<&str>().copied()).unwrap_or("");
            assert!(msg.contains("side_a must be exactly +1 or -1"), "side_a = {bad}: panic {msg:?} must name the polarity rule");
        }
    }

    #[test]
    fn apply_new_position_rejects_each_single_field_forgery() {
        let cases: &[(&str, fn(&mut NewPosition))] = &[
            ("recomputed Rfq.id(Terms) != claimed terms_id", |nb| nb.im_bps_a = 0),
            ("recomputed Rfq.id(Terms) != claimed terms_id", |nb| nb.terms_id[0] ^= 0xFF),
            ("entry_rate != first word of signed data", |nb| nb.entry_rate += 1),
            // F-2 (Terms 2.1): a flipped side no longer reproduces the signed id — the circuit rejects it.
            ("recomputed Rfq.id(Terms) != claimed terms_id", |nb| nb.side_a = -nb.side_a),
            ("sigB does not recover partyB", |nb| {
                let stranger = SigningKey::from_bytes(&[0x44u8; 32].into()).unwrap();
                let digest = eip712_digest(&nb.domain_separator, &nb.terms_id);
                nb.sig_b = nb_sign(&stranger, &digest);
            }),
            ("does not recover", |nb| nb.domain_separator = [0xEEu8; 32]),
        ];
        for &(expected, mutate) in cases {
            let mut nb = a_new_position();
            mutate(&mut nb);
            let err = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                apply_new_position(&nb)
            }))
            .expect_err(&format!("apply_new_position must panic for: {expected}"));
            let msg = err.downcast_ref::<String>().map(String::as_str)
                .or_else(|| err.downcast_ref::<&str>().copied()).unwrap_or("");
            assert!(msg.contains(expected), "panic {msg:?} must contain {expected:?}");
        }
    }

    #[test]
    fn new_position_any_signed_im_bps_binds() {
        let build = |bps_a: u16, bps_b: u16| -> NewPosition {
            let party_a = new_party_a();
            let party_b = new_party_b();
            let oracle = [0u8; 20];
            let (quantity, entry_rate, expiry) = (1_000_000u128, 1_080_000u128, 1_700_000_000u64);
            let (mm_pct, nonce, cure_window, pair_tag) = (5_000u16, 1u64, 0u64, [0x02u8; 32]);
            let data = nb_data_for_entry(entry_rate);
            let terms_id = terms_id(&party_a, &party_b, &oracle, &pair_tag, quantity,
                bps_a, bps_b, mm_pct, expiry, nonce, cure_window, 0, 0, &data, 1u8, 1);
            let domain_separator = nb_domain();
            let digest = eip712_digest(&domain_separator, &terms_id);
            NewPosition { terms_id, party_a, party_b, oracle, quantity, entry_rate, side_a: 1, expiry,
                im_bps_a: bps_a, im_bps_b: bps_b, instrument: 1, pair_tag, mm_pct, nonce, cure_window,
                payout_pref_a: 0, payout_pref_b: 0, data,
                sig_a: nb_sign(&nb_sk_a(), &digest), sig_b: nb_sign(&nb_sk_b(), &digest), domain_separator }
        };
        // The static MIN_IM_BPS floor was REMOVED (pure scenario-ES margin): any party-signed
        // im_bps binds, down to 1 bp. Risk coverage comes from the scenario-ES imRequirements.
        assert_new_position_bound(&build(781, 781));
        assert_new_position_bound(&build(1, 1));
        assert_new_position_bound(&build(1, 780));
    }

    #[test]
    fn apply_new_boxes_to_book_pushes_both_seats() {
        let nb = a_new_position();
        let mk = |owner: [u8; 20]| {
            let mut acct = Account::default();
            acct.account_owner = owner;
            (acct, empty_ri())
        };
        let mut accounts = vec![mk(new_party_a()), mk(new_party_b())];
        let out = apply_new_boxes_to_book(&mut accounts, std::slice::from_ref(&nb), 0);
        assert!(out.rejected.is_empty(), "both parties present ⇒ no rejection");
        assert_eq!(out.opened, vec![nb.terms_id], "the opened set carries the finished open");
        assert_eq!(accounts[0].1.positions.len(), 1, "A leaf gained the position");
        assert_eq!(accounts[1].1.positions.len(), 1, "B leaf gained the position");
        assert_eq!(accounts[0].1.positions[0].side, 1, "A takes the signed side");
        assert_eq!(accounts[1].1.positions[0].side, -1, "B takes the mirrored side");
    }

    #[test]
    #[should_panic(expected = "duplicate terms_id")]
    fn apply_new_boxes_to_book_rejects_duplicate_terms_id() {
        let nb = a_new_position();
        let mk = |owner: [u8; 20]| {
            let mut acct = Account::default();
            acct.account_owner = owner;
            (acct, empty_ri())
        };
        let mut accounts = vec![mk(new_party_a()), mk(new_party_b())];
        let dupes = [nb.clone(), nb];
        let _ = apply_new_boxes_to_book(&mut accounts, &dupes, 0);
    }

    #[test]
    fn empty_sig_contract_party_folds_and_emits_im_requirement() {
        let mut nb = a_new_position();
        nb.sig_a = Vec::new();
        let mk = |owner: [u8; 20]| { let mut a = Account::default(); a.account_owner = owner; (a, empty_ri()) };
        let mut accounts = vec![mk(new_party_a()), mk(new_party_b())];
        let out = apply_new_boxes_to_book(&mut accounts, std::slice::from_ref(&nb), 0);
        assert!(out.rejected.is_empty(), "empty-sig contract party still folds (not rejected)");
        assert_eq!(out.opened, vec![nb.terms_id], "the id surfaces in openedPositionIds ⇒ opened[id] re-asserted on-chain");
        assert_eq!(accounts[0].1.positions.len(), 1, "A (contract) leaf gained the position");
        assert_eq!(accounts[1].1.positions.len(), 1, "B leaf gained the mirrored position");
        let ims = im_requirements_for(new_party_a(), &accounts[0].1.positions, &test_table());
        assert_eq!(ims.len(), 1, "A's netting-set imRequirement is emitted");
        assert_eq!(ims[0].cp, new_party_b(), "A's imRequirement faces B");
        assert!(ims[0].usd > 0, "the contract party carries a real IM claim (the breach-then-restore money-shot)");
    }

    #[test]
    #[should_panic(expected = "sigB does not recover partyB")]
    fn empty_sig_a_still_enforces_nonempty_sigb() {
        let mut nb = a_new_position();
        nb.sig_a = Vec::new();
        let stranger = SigningKey::from_bytes(&[0x55u8; 32].into()).unwrap();
        let digest = eip712_digest(&nb.domain_separator, &nb.terms_id);
        nb.sig_b = nb_sign(&stranger, &digest);
        assert_new_position_bound(&nb);
    }

    #[test]
    #[should_panic(expected = "sigA does not recover partyA")]
    fn empty_sig_b_still_enforces_nonempty_siga() {
        let mut nb = a_new_position();
        nb.sig_b = Vec::new();
        let stranger = SigningKey::from_bytes(&[0x66u8; 32].into()).unwrap();
        let digest = eip712_digest(&nb.domain_separator, &nb.terms_id);
        nb.sig_a = nb_sign(&stranger, &digest);
        assert_new_position_bound(&nb);
    }

    #[test]
    fn empty_sig_skip_preserves_position_economics() {
        let full = a_new_position();
        let mut empty = full.clone();
        empty.sig_a = Vec::new();
        empty.sig_b = Vec::new();
        let locked_full = apply_new_position(&full);
        let locked_empty = apply_new_position(&empty);
        assert!(matches!(locked_full, NewPositionLock::Locked { .. }), "signed twin locks");
        assert_eq!(locked_full, locked_empty, "empty-sig path is economically byte-identical to the signed path");
    }

    #[test]
    #[should_panic(expected = "recomputed Rfq.id(Terms) != claimed terms_id")]
    fn empty_sigs_still_bind_params_via_terms_id() {
        let mut nb = a_new_position();
        nb.sig_a = Vec::new();
        nb.sig_b = Vec::new();
        nb.im_bps_a = nb.im_bps_a.wrapping_add(1);
        assert_new_position_bound(&nb);
    }
}
