//! Wire/serde schema for the zk-IM proof: guest stdin inputs and committed public-value outputs.
//! FIELD AND VARIANT ORDER IS FROZEN. The production wire is bincode — position-keyed, not name-keyed — so a
//! reorder silently re-keys the proof; the frozen-byte pins in `tests` are what turn that into a failure.
//! Scales: sensitivities and correlations 1e18 signed · rates and entry marks PRICE_SCALE · USD amounts (IM,
//! settlements, shortfalls) 6-dp · oracle prices Pyth-native, rescaled by their own `expo`. Core 2.0 keeps no
//! money in the tree — a leaf is `{account_owner, vm_equity, positions_root}`; collateral, IM and the deposit/debit watermarks all live on-chain in the till.
#![forbid(unsafe_code)]
#![deny(missing_docs)]

use serde::{Serialize, Deserialize};

/// One packed leg of a position set (legs collapse per factor).
#[derive(Clone, Copy, Serialize, Deserialize)]
pub struct RiskLeg {
    /// ISDA risk-factor bucket index (≤25 for FX).
    pub factor: u16,
    /// Signed sensitivity — the leg's contribution to its factor's netted delta.
    pub signed_qty: i128,
}

/// One account_owner's netting set; leaf key `account_id_single(account_owner)`.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct Account {
    /// Leaf owner (20-byte account_owner address).
    pub account_owner: [u8;20],
    /// The account_owner's open legs.
    pub positions: Vec<RiskLeg>,
    /// Net signed USD VM/PnL across open positions — the leaf's committed cumulative mark-to-market.
    #[serde(default)]
    pub vm_equity: i128,
    /// The VM committed in `root_prev`'s leaf — rebuilds the prior leaf ONLY; the new VM is recomputed in-guest from the proven mark and never read from here.
    #[serde(default)]
    pub prev_vm_equity: i128,
    /// Commitment to the account_owner's open positions (zero hash = empty).
    #[serde(default)]
    pub positions_root: [u8; 32],
}

/// One oracle price mark.
#[derive(Clone, Copy, Serialize, Deserialize)]
pub struct Mark {
    /// Marked rate (PRICE_SCALE fixed-point).
    pub rate: u128,
    /// Publish instant (Unix s).
    pub publish_time: u64,
}

/// Per-account risk/settlement witness (FX-forward only). The ISDA sensitivity vectors (`deltas`, `vegas`,
/// `curvatures`, `corr_matrix`, `fx_meta`) were DELETED in the scenario-ES migration — margin derives ONLY
/// from the bound positions against the committed scenario table.
#[derive(Clone, Serialize, Deserialize)]
pub struct RiskInputs {
    /// Whole-account settle signal — must be `None` (any `Some` is rejected).
    #[serde(default)]
    pub unconsumed_settle_residual: Option<i128>,

    /// Transparent opening of `positions_root`; empty ⇒ opaque path.
    #[serde(default)]
    pub positions: Vec<PositionRecord>,

    /// Unused by settlement.
    #[serde(default)]
    pub position_settlements: Vec<PositionSettlement>,

    /// Proven settle prices — the sole settlement price source.
    #[serde(default)]
    pub proven_twaps: Vec<ProvenTwap>,

    /// Proven hourly marks — the sole cumulative-VM price source; empty ⇒ no re-mark and the prior VM carries verbatim.
    #[serde(default)]
    pub proven_marks: Vec<ProvenMark>,
}

/// The single USD tree's root advance (mirrors `Types.Roots`).
#[derive(Clone, Copy, Serialize, Deserialize, Debug, PartialEq, Eq, Default)]
pub struct Roots {
    /// Keeper-supplied prior state root (CAS target).
    pub root_prev: [u8; 32],
    /// The advanced state root the fresh tree rebuilds to.
    pub root_new: [u8; 32],
    /// Prior account-registry root (CAS target).
    pub accounts_root_prev: [u8; 32],
    /// Advanced registry root, rebuilt over remaining.
    pub accounts_root_new: [u8; 32],
}

/// One per touched netting set: `applyState` writes `imRequired[acct][cp] = usd`, then coverage-compares it against live `value()`.
#[derive(Clone, Copy, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct ImRequirement {
    /// The account whose requirement this is.
    pub acct: [u8; 20],
    /// The counterparty defining the netting set.
    pub cp: [u8; 20],
    /// `position_im_floor` (`party_scenario_es` scenario-ES99, floored by seat `Σ pushed_im`) over `acct`'s positions facing `cp`, 6-dp USD.
    pub usd: u128,
}

/// One netted cash obligation due this fold; `applyState` pays it from the till by payee pref.
#[derive(Clone, Copy, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct Settlement {
    /// The paying side (till debited).
    pub payer: [u8; 20],
    /// The receiving side (till credited).
    pub payee: [u8; 20],
    /// 6-dp USD amount.
    pub usd: u128,
    /// Originating position `terms_id` (or handoff id).
    pub id: [u8; 32],
}

/// One per-position settlement signal (position + signed cash residual at close).
#[derive(Clone, Copy, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct PositionSettlement {
    /// The settling position's `Terms` digest.
    pub terms_id: [u8; 32],
    /// Signed realized residual (+gain / −loss).
    pub vm_realized: i128,
}

/// One under-margin CLAIM (mirrors `Types.DefaultRecord`) — the guest NAMES it, the on-chain grace gate decides the cut.
#[derive(Clone, Copy, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct DefaultRecord {
    /// The defaulting position's `Terms` digest.
    pub id: [u8; 32],
    /// The defaulting account_owner.
    pub account_owner: [u8; 20],
    /// The netting-set counterparty (loss destination).
    pub counterparty: [u8; 20],
    /// Claimed uncovered loss, 6-dp USD (named, not clamped).
    pub shortfall: u128,
}

/// One open position on a account_owner's leaf.
#[derive(Clone, Copy, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct PositionRecord {
    /// Position identity — the `Terms` digest.
    pub terms_id: [u8; 32],
    /// Matched-principal counterparty (loss destination / novation party).
    pub counterparty: [u8; 20],
    /// Pair oracle (binds the TWAP settle).
    pub oracle: [u8; 20],
    /// Notional.
    pub notional: u128,
    /// Entry rate the residual is computed against.
    pub entry_rate: u128,
    /// Signed side: +1 long, −1 short.
    pub side: i8,
    /// Expiry / settle instant (Unix s).
    pub expiry: u64,
    /// IM pushed at open.
    pub pushed_im: u128,
    /// Position market key `keccak256(abi.encode(instrument, pairTag))`.
    pub market_key: [u8; 32],
}

/// Proven (not signed) settle price for one position's close.
#[derive(Clone, Copy, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct ProvenTwap {
    /// Pyth feed id (low 20 bytes = position oracle).
    pub feed_id: [u8; 32],
    /// Close instant T (== position.expiry, Unix s).
    pub close_time: u64,
    /// Proven mean settle price in Pyth-native scale.
    pub settle_price: u128,
    /// Pyth exponent (residual rescales native price to the 1e6 position scale).
    pub expo: i32,
}

/// A position's consumed proven price, surfaced so the chain re-asserts its binding.
#[derive(Clone, Copy, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct ConsumedTwap {
    /// Pyth feed id the position settled against.
    pub feed_id: [u8; 32],
    /// Close instant T.
    pub close_time: u64,
    /// Consumed settle price in Pyth-native scale.
    pub twap: i128,
    /// Pyth exponent of `twap`.
    pub expo: i32,
}

/// Proven (not host-attested) hourly mark for one FX pair's cumulative VM — a shape-mirror of [`ProvenTwap`] riding the same write-once, Pyth-authenticated `boundTwap` rail, so every live position on the pair marks against one hourly fix.
#[derive(Clone, Copy, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct ProvenMark {
    /// Pyth feed id (low 20 bytes = the pair oracle, via `feed_id_oracle`).
    pub feed_id: [u8; 32],
    /// The Pyth-bound `closeTime` for this hourly fix.
    pub mark_time: u64,
    /// Pyth-native mark price — asserted `== boundTwap[feedId][markTime]` on-chain.
    pub price: u128,
    /// Pyth exponent (rescales the native price to the 1e6 position scale).
    pub expo: i32,
}

/// A consumed proven mark, surfaced so the chain re-asserts its `boundTwap` binding — a byte-exact shape-mirror of [`ConsumedTwap`].
#[derive(Clone, Copy, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct ConsumedMark {
    /// Pyth feed id the position(es) marked against.
    pub feed_id: [u8; 32],
    /// The hourly mark instant.
    pub mark_time: u64,
    /// Consumed mark price in Pyth-native scale, surfaced signed.
    pub price: i128,
    /// Pyth exponent of `price`.
    pub expo: i32,
}

/// One held position: a due position on a paused pair, skipped instead of force-settled.
#[derive(Clone, Copy, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct PausedHold {
    /// Held position's market key (re-asserted `paused == true`).
    pub market_key: [u8; 32],
    /// Held position's identity.
    pub position_id: [u8; 32],
}

/// A newly-`Bound` position to lock in-proof (the `openLock` payload).
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct NewPosition {
    /// Position identity — `Rfq.id(terms)`.
    pub terms_id: [u8; 32],
    /// Party A (first seat).
    pub party_a: [u8; 20],
    /// Party B (second seat).
    pub party_b: [u8; 20],
    /// Pair oracle.
    pub oracle: [u8; 20],
    /// Base quantity.
    pub quantity: u128,
    /// Entry rate (PRICE_SCALE units).
    pub entry_rate: u128,
    /// A's signed side: +1 long / −1 short.
    pub side_a: i8,
    /// Expiry / settle instant (Unix s).
    pub expiry: u64,
    /// A's IM bps (party-signed; no static minimum — margin is pure scenario-ES).
    pub im_bps_a: u16,
    /// B's IM bps (party-signed; no static minimum — margin is pure scenario-ES).
    pub im_bps_b: u16,
    /// Instrument tag.
    pub instrument: u8,
    /// Terms `pairTag` (pause key).
    pub pair_tag: [u8; 32],
    /// Terms `mmPct` (MM as % of IM, 1e4 = 100%).
    pub mm_pct: u16,
    /// Terms `nonce`.
    pub nonce: u64,
    /// Terms `cureWindow` (0 = permissionless).
    pub cure_window: u64,
    /// Terms `payoutPrefA` (0 = base-only, 1 = base + my-accepted-set). Terms 2.0.
    pub payout_pref_a: u8,
    /// Terms `payoutPrefB` (0 = base-only, 1 = base + my-accepted-set). Terms 2.0.
    pub payout_pref_b: u8,
    /// Terms `data` (side + strike/rate; first word = entry_rate).
    pub data: Vec<u8>,
    /// A's 65-byte sig over `digest(domain, terms_id)`.
    pub sig_a: Vec<u8>,
    /// B's 65-byte sig over `digest(domain, terms_id)`.
    pub sig_b: Vec<u8>,
    /// EIP-712 domain separator (pinned to `DOMAIN` by `state_transition`).
    pub domain_separator: [u8; 32],
}

/// Novation kind: A consented (Voluntary) vs A defaulted (Forced).
#[derive(Clone, Copy, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum NovationKind {
    /// A consented.
    Voluntary,
    /// A defaulted.
    Forced,
}

/// One novation surfaced in public values (mirrors `Types.Novation`).
#[derive(Clone, Copy, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct Novation {
    /// A's old position id (closed).
    pub old_id: [u8; 32],
    /// B's inherited position's new id.
    pub new_id: [u8; 32],
    /// A (outgoing) — position closed, absorbs the mark cost.
    pub party_a: [u8; 20],
    /// B (staying) — untouched.
    pub party_b: [u8; 20],
    /// C (incoming) — inherits the position.
    pub party_c: [u8; 20],
    /// Fresh IM claim for C, USD.
    pub c_im: u128,
    /// 0 = voluntary, 1 = forced.
    pub forced: u8,
    /// C's SIGNED market price (the RFQ quote) — the funded mark the A↔B P&L settles at, never a keeper input; 0 on the forced path.
    pub transfer_price: u128,
    /// C's compensation, if any (maker spread), bound into the takeover commitment; 0 on the forced path.
    pub spread: u128,
    /// Single-use per-position nonce C signed (a `novationNonce` bump bars replay); 0 on the forced path.
    pub nonce: u64,
    /// C's consent deadline; `applyState` rejects a consumption past it; 0 on the forced path.
    pub deadline: u64,
}

/// Full `transfer_as_close` witness threaded per committed `Novation` — priced by C's signed maker QUOTE, not a proven-TWAP oracle mark.
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct NovationWitness {
    /// A's position being novated.
    pub a_position: PositionRecord,
    /// The handoff mark the A↔B P&L settles at; on the voluntary path the guest asserts it equals `transfer_price`, so a keeper cannot substitute a raw mark.
    pub mark: u128,
    /// C's fresh netted IM claim for the inherited position, USD.
    pub c_im: u128,
    /// A's address (outgoing leaf owner).
    pub party_a: [u8; 20],
    /// C's address (inheriting maker).
    pub party_c: [u8; 20],
    /// Voluntary vs forced.
    pub kind: NovationKind,
    /// C's signed market price = the funded `mark`; C signs the price it PAYS (voluntary path only, inert when forced).
    pub transfer_price: u128,
    /// C's compensation (maker spread), bound into the `NovationTakeover` consent.
    pub spread: u128,
    /// C's own bilateral IM ratio (bps) — C signs the `im_bps` it carries on the inherited seat.
    pub c_im_bps: u16,
    /// Single-use per-position nonce C signed.
    pub nonce: u64,
    /// C's consent deadline.
    pub deadline: u64,
    /// The EIP-712 domain separator C signed under (bars cross-chain replay).
    pub domain_separator: [u8; 32],
    /// C's 65-byte `NovationTakeover` signature (`r‖s‖v`); recovered signer must be `party_c`.
    pub sig_c: Vec<u8>,
}

/// One bilateral unwind surfaced in public values (mirrors `Types.Unwind`) — a live position torn up at a
/// mutually-signed close price. No partyC, no newId: no one steps in, the leaf is retired. The tail
/// (`close_price..deadline`) is exactly what `finalizeUnwinds` recomputes the single-use `unwindAuth` commitment
/// from, and both parties signed the SAME `Closeout` digest over `(old_id, close_price, nonce, deadline)`.
#[derive(Clone, Copy, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct Unwind {
    /// The position torn up (A's `Terms` digest) — the wire field is `oldId`.
    pub old_id: [u8; 32],
    /// Party A (first seat / leaf owner).
    pub party_a: [u8; 20],
    /// Party B (second seat / A's matched counterparty).
    pub party_b: [u8; 20],
    /// The mutually-signed tear-up price — no oracle substitution.
    pub close_price: u128,
    /// Single-use per-position nonce both parties signed (an `unwindNonce` bump bars replay).
    pub nonce: u64,
    /// Consent deadline; `finalizeUnwinds` rejects a consumption past it.
    pub deadline: u64,
}

/// Full `unwind_close` witness threaded per committed [`Unwind`] — BOTH A and B sign the SAME `Closeout` digest to
/// tear up the position at a mutually-agreed `close_price`. Mirrors [`NovationWitness`] minus the incoming party.
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct UnwindWitness {
    /// A's position being torn up (the committed leaf for `old_id`).
    pub a_position: PositionRecord,
    /// The mutually-signed close price the A↔B P&L settles at; bound into the digest both parties sign.
    pub close_price: u128,
    /// Party A (first seat / leaf owner) — must recover from one of the two signatures.
    pub party_a: [u8; 20],
    /// Party B (second seat / A's counterparty) — must recover from the other signature.
    pub party_b: [u8; 20],
    /// Single-use per-position nonce both parties signed.
    pub nonce: u64,
    /// Consent deadline both parties signed.
    pub deadline: u64,
    /// The EIP-712 domain separator both signed under (bars cross-deployment replay).
    pub domain_separator: [u8; 32],
    /// A's 65-byte `Closeout` signature (`r‖s‖v`).
    pub sig_a: Vec<u8>,
    /// B's 65-byte `Closeout` signature (`r‖s‖v`).
    pub sig_b: Vec<u8>,
}

/// One A→C default-closeout_novation in the public values (mirrors `Types.CloseoutNovation`).
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct CloseoutNovation {
    /// A's failed position id.
    pub old_id: [u8; 32],
    /// B's inherited position's new id.
    pub new_id: [u8; 32],
    /// A — defaulted, position closed.
    pub party_a: [u8; 20],
    /// B — untouched, continues facing C.
    pub party_b: [u8; 20],
    /// C — RFQ winner, inherits the leg.
    pub party_c: [u8; 20],
    /// Proven-TWAP key for the handoff mark.
    pub feed_id: [u8; 32],
    /// Handoff instant.
    pub close_time: u64,
    /// The handoff mark (re-asserted on-chain).
    pub handoff_mark: i128,
    /// C's signed compensation (A → C).
    pub spread: u128,
    /// C's fresh IM (>= floor).
    pub c_im: u128,
    /// A's free after close + spread (observational).
    pub a_residual: u128,
    /// The uncovered spread (named default loss; 0 = fully covered).
    pub shortfall: u128,
    /// Per-position closeout_novation nonce.
    pub nonce: u64,
    /// The EIP-712 domain C consented under.
    pub domain_separator: [u8; 32],
    /// A's authorized margin snapshot (re-bound by `novationAuth`).
    pub m_a_authorized: u128,
}

/// Full `closeout_novation_close` witness threaded per committed `CloseoutNovation`.
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct CloseoutNovationWitness {
    /// A's failing position.
    pub a_position: PositionRecord,
    /// The proven handoff mark.
    pub proven_twap: ProvenTwap,
    /// C's posted IM for the inherited leg.
    pub c_im: u128,
    /// C's signed compensation.
    pub spread: u128,
    /// A — the defaulting leaf owner.
    pub party_a: [u8; 20],
    /// C — the inheriting maker.
    pub party_c: [u8; 20],
    /// C's 65-byte FailoverConsent signature (`r‖s‖v`).
    pub sig_c: Vec<u8>,
    /// The per-position closeout_novation nonce C signed.
    pub nonce: u64,
    /// C's consent deadline.
    pub deadline: u64,
    /// The EIP-712 domain separator C signed under.
    pub domain_separator: [u8; 32],
    /// A's authorized margin snapshot (asserted `a_free + a_locked >= m_a_authorized`).
    pub m_a_authorized: u128,
    /// Terms `pairTag`.
    pub pair_tag: [u8; 32],
    /// Terms `quantity`.
    pub quantity: u128,
    /// A's IM bps.
    pub im_bps_a: u16,
    /// B's IM bps.
    pub im_bps_b: u16,
    /// Terms `mmPct`.
    pub mm_pct: u16,
    /// Terms `nonce`.
    pub terms_nonce: u64,
    /// Terms `cureWindow`.
    pub cure_window: u64,
    /// Terms `payoutPrefA` (Terms 2.0 — bound into terms_id).
    pub payout_pref_a: u8,
    /// Terms `payoutPrefB` (Terms 2.0 — bound into terms_id).
    pub payout_pref_b: u8,
    /// Terms `data` (first word = entry_rate).
    pub data: Vec<u8>,
    /// Terms `instrument`.
    pub instrument: u8,
}

/// What sits at the end of an smt2 sibling path (see docs/smt-encoding-spec.md).
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum SmtTerminal {
    /// The key is present with this leaf VALUE (the pre-hash encoding output, e.g. `account_leaf`).
    Leaf([u8; 32]),
    /// The key's path lands in an empty subtree — absence.
    Empty,
    /// The key's path lands on a DIFFERENT single-leaf subtree `(other_key, other_value)` — absence.
    OtherLeaf([u8; 32], [u8; 32]),
}

/// Preimage proof of a sibling node's kind, needed only on delete — the 0x00/0x01 domain tags admit exactly one preimage shape per hash, so the claim is unforgeable.
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum SiblingKind {
    /// `sibling == H_leaf(key, value)` — a single-leaf subtree; it rises on delete.
    Leaf {
        /// The sibling leaf's key.
        key: [u8; 32],
        /// The sibling leaf's value.
        value: [u8; 32],
    },
    /// `sibling == H_node(left, right)` — an internal node (≥ 2 leaves below); it does not rise.
    Node {
        /// Left child hash.
        left: [u8; 32],
        /// Right child hash.
        right: [u8; 32],
    },
}

/// smt2 inclusion/absence witness. `siblings` leaf→root; `depth = siblings.len() ≤ 256`.
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct SmtWitness {
    /// The 256-bit key being proven (MSB-first path bits).
    pub key: [u8; 32],
    /// Sibling hashes, leaf→root order.
    pub siblings: Vec<[u8; 32]>,
    /// What the path lands on.
    pub terminal: SmtTerminal,
    /// Delete-only promotion disambiguator (None for update/insert).
    pub delete_kind: Option<SiblingKind>,
}

/// One touched account: prior leaf fields + risk witness + tree witnesses.
#[derive(Clone, Serialize, Deserialize)]
pub struct TouchedAccount {
    /// Prior leaf fields (incl. `prev_vm_equity`) — bound to the running root by `state_witness`.
    pub account: Account,
    /// The account's risk/settlement witness.
    pub risk: RiskInputs,
    /// Sequential witness against the STATE tree (op=2 contract).
    pub state_witness: SmtWitness,
    /// Sequential witness against the REGISTRY tree; `Some` IFF membership changes.
    pub registry_witness: Option<SmtWitness>,
}

/// The single USD book: `(root_prev, accounts_root_prev, touched_accounts)`.
pub type TouchedBook = ([u8; 32], [u8; 32], Vec<TouchedAccount>);

#[cfg(test)]
mod tests {
    use super::*;

    fn json_stable<T>(v: &T)
    where
        T: Serialize + for<'de> Deserialize<'de>,
    {
        let s = serde_json::to_string(v).expect("serialize");
        let back: T = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(s, serde_json::to_string(&back).expect("re-serialize"), "wire encoding is stable");
    }

    #[test]
    fn account_fills_optional_fields_from_default() {
        let json = r#"{"account_owner":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"positions":[]}"#;
        let a: Account = serde_json::from_str(json).expect("minimal account deserialises");
        assert_eq!(a.vm_equity, 0, "vm defaults to 0");
        assert_eq!(a.prev_vm_equity, 0, "prev_vm defaults to 0");
        assert_eq!(a.positions_root, [0u8; 32]);
        json_stable(&a);
    }

    #[test]
    fn risk_inputs_optional_vecs_default_empty() {
        let json = r#"{}"#;
        let ri: RiskInputs = serde_json::from_str(json).expect("minimal risk inputs deserialise");
        assert!(ri.positions.is_empty(), "positions defaults empty");
        assert!(ri.proven_marks.is_empty(), "proven_marks defaults empty");
        assert!(ri.proven_twaps.is_empty(), "proven_twaps defaults empty");
        assert!(ri.unconsumed_settle_residual.is_none(), "settle residual defaults None");
        json_stable(&ri);
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Each hex chunk is one bincode field in declaration order: u32 LE enum tags,
    /// u64 LE lengths, one-byte Option tags, then raw field bytes.
    #[test]
    fn smt2_wire_types_bincode_bytes_are_frozen() {
        const TERMINAL_HEX: &str = concat!(
            "02000000",
            "1111111111111111111111111111111111111111111111111111111111111111",
            "2222222222222222222222222222222222222222222222222222222222222222",
        );
        let terminal = SmtTerminal::OtherLeaf([0x11; 32], [0x22; 32]);
        assert_eq!(
            hex(&bincode::serialize(&terminal).expect("terminal")),
            TERMINAL_HEX,
            "SmtTerminal bincode bytes moved — variant order or payload shape changed",
        );

        const KIND_LEAF_HEX: &str = concat!(
            "00000000",
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
        );
        let kind_leaf = SiblingKind::Leaf { key: [0x0B; 32], value: [0x0C; 32] };
        assert_eq!(
            hex(&bincode::serialize(&kind_leaf).expect("kind_leaf")),
            KIND_LEAF_HEX,
            "SiblingKind::Leaf bincode bytes moved — variant order or field order changed",
        );

        const KIND_NODE_HEX: &str = concat!(
            "01000000",
            "0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d",
            "0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e",
        );
        let kind_node = SiblingKind::Node { left: [0x0D; 32], right: [0x0E; 32] };
        assert_eq!(
            hex(&bincode::serialize(&kind_node).expect("kind_node")),
            KIND_NODE_HEX,
            "SiblingKind::Node bincode bytes moved — variant order or field order changed",
        );

        const WITNESS_HEX: &str = concat!(
            "3333333333333333333333333333333333333333333333333333333333333333",
            "0200000000000000",
            "4444444444444444444444444444444444444444444444444444444444444444",
            "5555555555555555555555555555555555555555555555555555555555555555",
            "00000000",
            "6666666666666666666666666666666666666666666666666666666666666666",
            "01",
            "01000000",
            "7777777777777777777777777777777777777777777777777777777777777777",
            "8888888888888888888888888888888888888888888888888888888888888888",
        );
        let witness = SmtWitness {
            key: [0x33; 32],
            siblings: vec![[0x44; 32], [0x55; 32]],
            terminal: SmtTerminal::Leaf([0x66; 32]),
            delete_kind: Some(SiblingKind::Node { left: [0x77; 32], right: [0x88; 32] }),
        };
        assert_eq!(
            hex(&bincode::serialize(&witness).expect("witness")),
            WITNESS_HEX,
            "SmtWitness bincode bytes moved — field order changed",
        );

        const TOUCHED_HEX: &str = concat!(
            "0000000000000000000000000000000000000000",
            "0000000000000000",
            "00000000000000000000000000000000",
            "00000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "00",
            "0000000000000000",
            "0000000000000000",
            "0000000000000000",
            "0000000000000000",
            "3333333333333333333333333333333333333333333333333333333333333333",
            "0200000000000000",
            "4444444444444444444444444444444444444444444444444444444444444444",
            "5555555555555555555555555555555555555555555555555555555555555555",
            "00000000",
            "6666666666666666666666666666666666666666666666666666666666666666",
            "01",
            "01000000",
            "7777777777777777777777777777777777777777777777777777777777777777",
            "8888888888888888888888888888888888888888888888888888888888888888",
            "00",
        );
        let touched = TouchedAccount {
            account: Account::default(),
            risk: RiskInputs {
                unconsumed_settle_residual: None, positions: vec![], position_settlements: vec![],
                proven_twaps: vec![], proven_marks: vec![],
            },
            state_witness: witness.clone(),
            registry_witness: None,
        };
        assert_eq!(
            hex(&bincode::serialize(&touched).expect("touched")),
            TOUCHED_HEX,
            "TouchedAccount bincode bytes moved — field order changed",
        );
    }

}
