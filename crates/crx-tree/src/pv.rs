//! The 15-row public-values schema — byte-for-byte the guest's committed
//! `PublicValuesStruct` (mirrored on-chain in `Types.sol`). Field TYPES and ORDER are
//! VKEY-AFFECTING: a mismatch decodes every later field from the wrong ABI offset.

use anyhow::Result;
use alloy::sol;
use alloy::sol_types::SolValue;
use im_types as st;

sol! {
    /// The single USD tree's root advance.
    struct RootsSol {
        bytes32 rootPrev;
        bytes32 rootNew;
        bytes32 accountsRootPrev;
        bytes32 accountsRootNew;
    }
    /// One under-margin claim — the guest names it, the on-chain grace gate decides.
    struct DefaultSol {
        bytes32 id;
        address accountOwner;
        address counterparty;
        uint128 usd;
    }
    /// One consumed settle price, asserted == `boundTwap[feedId][closeTime]`.
    struct ConsumedTwapSol {
        bytes32 feedId;
        uint64  closeTime;
        int256  twap;
        int32   expo;
    }
    /// One novation, USD-denominated.
    struct NovationSol {
        bytes32 oldId;
        bytes32 newId;
        address partyA;
        address partyB;
        address partyC;
        uint128 cIm;
        uint8   forced;
        uint128 transferPrice;
        uint128 spread;
        uint64  nonce;
        uint64  deadline;
    }
    /// One default-closeout A→C handoff, USD-denominated.
    struct CloseoutNovationSol {
        bytes32 oldId;
        bytes32 newId;
        address partyA;
        address partyB;
        address partyC;
        bytes32 feedId;
        uint64  closeTime;
        int256  handoffMark;
        uint128 spread;
        uint128 cIm;
        uint128 aResidual;
        uint128 shortfall;
        uint64  nonce;
        bytes32 domainSeparator;
        uint128 mAAuthorized;
    }
    /// One due position skipped on pause grounds.
    struct PausedHoldSol {
        bytes32 marketKey;
        bytes32 positionId;
    }
    /// One consumed hourly mark, asserted == `boundTwap[feedId][markTime]`.
    struct ConsumedMarkSol {
        bytes32 feedId;
        uint64  markTime;
        int256  price;
        int32   expo;
    }
    /// One per touched netting set. `applyState` writes `imRequired[acct][cp] = usd`.
    struct ImRequirementSol {
        address acct;
        address cp;
        uint256 usd;
    }
    /// One netted cash obligation due this fold; `applyState` pays it from the till.
    struct SettlementSol {
        address payer;
        address payee;
        uint256 usd;
        bytes32 id;
    }
    /// One bilateral unwind.
    struct UnwindSol {
        bytes32 oldId;
        address partyA;
        address partyB;
        uint128 closePrice;
        uint64  nonce;
        uint64  deadline;
    }
    /// The FINAL 15-row public values (the guest commits `pv.abi_encode()`). Field
    /// order is VKEY-AFFECTING.
    struct PublicValuesStruct {
        RootsSol roots;                          // 1
        DefaultSol[] defaults;                   // 2
        ConsumedTwapSol[] consumedTwaps;         // 3
        NovationSol[] novations;                 // 4
        CloseoutNovationSol[] closeoutNovations; // 5
        bytes32 eventsCommitment;                // 6
        uint64  proofTime;                       // 7
        bytes32 domainSeparator;                 // 8
        PausedHoldSol[] pausedHolds;             // 9
        bytes32 scenarioRoot;                    // 10
        ConsumedMarkSol[] consumedMarks;         // 11
        bytes32[] openedPositionIds;             // 12
        ImRequirementSol[] imRequirements;       // 13
        SettlementSol[] settlements;             // 14
        UnwindSol[] unwinds;                     // 15
    }
}

/// One fold's decoded public values, in the vendored engine's native types.
#[derive(Clone)]
pub struct DecodedPv {
    pub roots: st::Roots,
    pub consumed_twaps: Vec<st::ConsumedTwap>,
    pub novations: Vec<st::Novation>,
    pub events_commitment: [u8; 32],
    pub proof_time: u64,
    pub domain_separator: [u8; 32],
    pub scenario_root: [u8; 32],
    pub consumed_marks: Vec<st::ConsumedMark>,
    pub opened_position_ids: Vec<[u8; 32]>,
    /// Rows this replay does not model yet — non-empty fails loudly, never drifts.
    pub closeout_novations_len: usize,
    pub unwinds_len: usize,
    pub defaults_len: usize,
    pub paused_holds: Vec<st::PausedHold>,
}

/// Decode the 15-row `PublicValuesStruct` the guest committed.
pub fn decode_public_values(public_values: &[u8]) -> Result<DecodedPv> {
    let pv = PublicValuesStruct::abi_decode(public_values)
        .map_err(|e| anyhow::anyhow!("decode 15-row PublicValuesStruct: {e}"))?;

    let roots = st::Roots {
        root_prev: pv.roots.rootPrev.0,
        root_new: pv.roots.rootNew.0,
        accounts_root_prev: pv.roots.accountsRootPrev.0,
        accounts_root_new: pv.roots.accountsRootNew.0,
    };

    let consumed_twaps = pv
        .consumedTwaps
        .iter()
        .map(|t| {
            Ok(st::ConsumedTwap {
                feed_id: t.feedId.0,
                close_time: t.closeTime,
                twap: i128::try_from(t.twap).map_err(|_| anyhow::anyhow!("twap exceeds i128"))?,
                expo: t.expo,
            })
        })
        .collect::<Result<_>>()?;

    let consumed_marks = pv
        .consumedMarks
        .iter()
        .map(|m| {
            Ok(st::ConsumedMark {
                feed_id: m.feedId.0,
                mark_time: m.markTime,
                price: i128::try_from(m.price).map_err(|_| anyhow::anyhow!("mark exceeds i128"))?,
                expo: m.expo,
            })
        })
        .collect::<Result<_>>()?;

    let novations = pv
        .novations
        .iter()
        .map(|n| st::Novation {
            old_id: n.oldId.0,
            new_id: n.newId.0,
            party_a: n.partyA.into_array(),
            party_b: n.partyB.into_array(),
            party_c: n.partyC.into_array(),
            c_im: n.cIm,
            forced: n.forced,
            transfer_price: n.transferPrice,
            spread: n.spread,
            nonce: n.nonce,
            deadline: n.deadline,
        })
        .collect();

    let paused_holds = pv
        .pausedHolds
        .iter()
        .map(|h| st::PausedHold { market_key: h.marketKey.0, position_id: h.positionId.0 })
        .collect();

    Ok(DecodedPv {
        roots,
        consumed_twaps,
        novations,
        events_commitment: pv.eventsCommitment.0,
        proof_time: pv.proofTime,
        domain_separator: pv.domainSeparator.0,
        scenario_root: pv.scenarioRoot.0,
        consumed_marks,
        opened_position_ids: pv.openedPositionIds.iter().map(|b| b.0).collect(),
        closeout_novations_len: pv.closeoutNovations.len(),
        unwinds_len: pv.unwinds.len(),
        defaults_len: pv.defaults.len(),
        paused_holds,
    })
}
