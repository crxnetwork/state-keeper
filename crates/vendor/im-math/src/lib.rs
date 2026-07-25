//! Pure wide-math kernels for the scenario-ES margin: U256 exact products, directed /ONE folds, isqrt.
//! The ISDA IM ρ-form kernels (quadratic-form aggregation, concentration CR/f_kl) were DELETED in the
//! scenario-matrix ES99 migration; what remains is the scale-agnostic arithmetic the ES kernel builds on.
//! SCALE. Everything is 1e18 fixed-point (`ONE`). No 1e6 anywhere — token-decimal conversion happens outside
//! this crate. Every function here is vkey-affecting.
//! ROUNDING. `mul_div_one` floors; `mul_div_one_ceil` is that product rounded up and is what a margin
//! requirement must use, because a floored requirement under-margins. `isqrt`, `U256::div_u128` are exact
//! floors; `U256::div_u128_ceil` is the exact ceiling — the DIRECTED fold for loss-increasing contributions.
//! OVERFLOW. Nothing saturates or clamps: every widening step is checked and panics, so an unsatisfiable
//! proof beats a silently wrong margin.
#![forbid(unsafe_code)]
#![deny(missing_docs)]

use im_calibration::*;

/// Minimal unsigned 256-bit integer (hi:lo).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct U256 {
    /// High 128 bits.
    pub hi: u128,
    /// Low 128 bits.
    pub lo: u128,
}

impl U256 {
    /// The zero value.
    pub const ZERO: U256 = U256 { hi: 0, lo: 0 };

    /// Checked full 256-bit product of two u128 (None on 256-bit overflow).
    pub fn checked_mul(a: u128, b: u128) -> Option<U256> {
        let mask = u64::MAX as u128;
        let (a0, a1) = (a & mask, a >> 64);
        let (b0, b1) = (b & mask, b >> 64);
        let p00 = a0 * b0;
        let p01 = a0 * b1;
        let p10 = a1 * b0;
        let p11 = a1 * b1;
        let mid = (p01 & mask) + (p10 & mask) + (p00 >> 64);
        let lo = (p00 & mask) + ((mid & mask) << 64);
        let hi = p11.checked_add((p01 >> 64) + (p10 >> 64) + (mid >> 64))?;
        Some(U256 { hi, lo })
    }

    /// Full 256-bit product; panics on 256-bit overflow.
    pub fn mul(a: u128, b: u128) -> U256 {
        U256::checked_mul(a, b).expect("U256::mul: 256-bit overflow")
    }

    /// 256-bit addition; panics on 256-bit overflow.
    pub fn add(self, o: U256) -> U256 {
        let (lo, c) = self.lo.overflowing_add(o.lo);
        let hi = self.hi
            .checked_add(o.hi).expect("U256::add: hi overflow")
            .checked_add(c as u128).expect("U256::add: carry overflow");
        U256 { hi, lo }
    }

    /// 256-bit subtraction `self − o`; panics on underflow (caller must prove `self >= o`).
    pub fn sub(self, o: U256) -> U256 {
        assert!(o.le(self), "U256::sub: underflow (o > self)");
        let (lo, borrow) = self.lo.overflowing_sub(o.lo);
        let hi = self.hi - o.hi - borrow as u128;
        U256 { hi, lo }
    }

    /// Checked full product `self · b` where `b` is a u128 (None on 256-bit overflow).
    pub fn checked_mul_u128(self, b: u128) -> Option<U256> {
        let lo_prod = U256::checked_mul(self.lo, b)?;
        let hi_prod = U256::checked_mul(self.hi, b)?;
        if hi_prod.hi != 0 { return None; }
        let shifted = U256 { hi: hi_prod.lo, lo: 0 };
        let (lo, c) = shifted.lo.overflowing_add(lo_prod.lo);
        let hi = shifted.hi.checked_add(lo_prod.hi)?.checked_add(c as u128)?;
        Some(U256 { hi, lo })
    }

    /// Exact floor division `self / d` by a non-zero u128; restoring bit-by-bit long division.
    pub fn div_u128(self, d: u128) -> U256 {
        assert!(d != 0, "U256::div_u128: division by zero");
        if self.hi == 0 {
            return U256 { hi: 0, lo: self.lo / d };
        }
        let mut q = U256 { hi: 0, lo: 0 };
        let mut rem: u128 = 0;
        for i in (0..256).rev() {
            let bit = if i >= 128 { (self.hi >> (i - 128)) & 1 } else { (self.lo >> i) & 1 };
            let carry = rem >> 127;
            let shifted = (rem << 1) | bit;
            let ge = carry == 1 || shifted >= d;
            if ge {
                rem = shifted.wrapping_sub(d);
                if i >= 128 { q.hi |= 1u128 << (i - 128); } else { q.lo |= 1u128 << i; }
            } else {
                rem = shifted;
            }
        }
        q
    }

    /// Exact ceiling division `ceil(self / d)` by a non-zero u128 — the DIRECTED fold a loss-increasing
    /// margin contribution must use (a floored one under-margins); panics on 256-bit overflow of the +1.
    pub fn div_u128_ceil(self, d: u128) -> U256 {
        let q = self.div_u128(d);
        let back = q.checked_mul_u128(d).expect("U256::div_u128_ceil: q·d overflow");
        if back == self {
            q
        } else {
            q.add(U256 { hi: 0, lo: 1 })
        }
    }

    /// Lexicographic `self <= o` over (hi, lo).
    pub fn le(self, o: U256) -> bool { (self.hi, self.lo) <= (o.hi, o.lo) }

    /// Floor integer sqrt; result fits u128.
    pub fn isqrt(self) -> u128 {
        if self.hi == 0 { return isqrt(self.lo); }
        let mut res: u128 = 0;
        let mut bit: u128 = 1u128 << 127;
        while bit != 0 {
            let cand = res | bit;
            let fits = matches!(U256::checked_mul(cand, cand), Some(sq) if sq.le(self));
            if fits { res = cand; }
            bit >>= 1;
        }
        res
    }
}

/// Integer floor square root ⌊√n⌋; total over all `u128`.
pub fn isqrt(n: u128) -> u128 {
    if n < 2 { return n; }
    let bits = 128 - n.leading_zeros();
    let mut x = 1u128 << ((bits + 1) / 2);
    loop {
        let y = (x + n / x) / 2;
        if y >= x { break; }
        x = y;
    }
    x
}

/// Exact `floor(a·b/ONE)` for 1e18 non-negative `a`,`b`; panics if the result exceeds u128.
pub fn mul_div_one(a: u128, b: u128) -> u128 {
    let (qa, ra) = (a / ONE, a % ONE);
    let (qb, rb) = (b / ONE, b % ONE);
    qa.checked_mul(qb).expect("mul_div_one: qa*qb overflow")
        .checked_mul(ONE).expect("mul_div_one: qa*qb*ONE overflow")
        .checked_add(qa.checked_mul(rb).expect("mul_div_one: qa*rb overflow")).expect("mul_div_one: +qa*rb overflow")
        .checked_add(ra.checked_mul(qb).expect("mul_div_one: ra*qb overflow")).expect("mul_div_one: +ra*qb overflow")
        .checked_add((ra * rb) / ONE).expect("mul_div_one: +ra*rb/ONE overflow")
}

/// `ceil(a·b/ONE)` — `mul_div_one` rounded up (never under-margins); panics on u128 overflow.
pub fn mul_div_one_ceil(a: u128, b: u128) -> u128 {
    let rem = (a % ONE) * (b % ONE);
    mul_div_one(a, b).checked_add((rem % ONE != 0) as u128).expect("mul_div_one_ceil: +round-up overflow")
}

#[cfg(test)]
mod u256_wide_tests {
    use super::*;

    fn val(u: U256) -> u128 {
        assert_eq!(u.hi, 0, "value does not fit u128");
        u.lo
    }

    #[test]
    fn u256_sub_and_le() {
        let a = U256::mul(u128::MAX, 3);
        let b = U256::mul(u128::MAX, 1);
        assert!(b.le(a) && !a.le(b), "ordering across the 128-bit boundary");
        assert_eq!(a.sub(b), U256::mul(u128::MAX, 2), "3x − 1x = 2x");
        assert_eq!(a.sub(a), U256 { hi: 0, lo: 0 }, "x − x = 0");
    }

    #[test]
    #[should_panic(expected = "underflow")]
    fn u256_sub_underflow_panics() {
        let a = U256 { hi: 0, lo: 1 };
        let b = U256 { hi: 0, lo: 2 };
        let _ = a.sub(b);
    }

    #[test]
    fn u256_checked_mul_u128_widens_and_detects_overflow() {
        let wide = U256 { hi: 0, lo: u128::MAX };
        let two = wide.checked_mul_u128(2).expect("fits");
        assert_eq!(two, U256 { hi: 1, lo: u128::MAX - 1 }, "2·(2^128−1) = 2^129 − 2");
        let max256 = U256 { hi: u128::MAX, lo: u128::MAX };
        assert!(max256.checked_mul_u128(2).is_none(), "product past 2^256 is rejected");
        assert_eq!(max256.checked_mul_u128(0).unwrap(), U256 { hi: 0, lo: 0 }, "·0 = 0");
    }

    #[test]
    fn u256_div_u128_exact_floor() {
        assert_eq!(val(U256 { hi: 0, lo: 100 }.div_u128(7)), 14, "floor(100/7)=14");
        let num = U256::mul(u128::MAX, 1_000_003);
        let d = 1_000_000_000_000_000_000u128;
        let q = num.div_u128(d);
        let qd = q.checked_mul_u128(d).expect("q·d fits");
        let rem = num.sub(qd);
        assert!(rem.hi == 0 && rem.lo < d, "remainder is in [0, d): exact floor division");
    }

    #[test]
    fn u256_div_u128_ceil_is_floor_or_floor_plus_one() {
        assert_eq!(val(U256 { hi: 0, lo: 100 }.div_u128_ceil(7)), 15, "ceil(100/7)=15");
        assert_eq!(val(U256 { hi: 0, lo: 98 }.div_u128_ceil(7)), 14, "ceil(98/7)=14 (exact stays exact)");
        assert_eq!(val(U256::ZERO.div_u128_ceil(7)), 0, "ceil(0/d)=0");
        let num = U256::mul(u128::MAX, 1_000_003);
        let d = 1_000_000_000_000_000_000u128;
        let fl = num.div_u128(d);
        let ce = num.div_u128_ceil(d);
        assert_eq!(ce, fl.add(U256 { hi: 0, lo: 1 }), "inexact wide division rounds up by exactly one");
        let exact = U256::mul(123_456_789, d);
        assert_eq!(exact.div_u128_ceil(d), exact.div_u128(d), "exact wide division does not round up");
    }

    #[test]
    fn u256_div_u128_matches_mul_div_one_where_it_fits() {
        const A: u128 = 71_000_000_000_000_000;
        for (a, b) in [(A, ONE + 7), (3 * ONE + 1, 5 * ONE + 9), (ONE, ONE), (0, ONE)] {
            let wide = U256::mul(a, b).div_u128(ONE);
            assert_eq!(val(wide), mul_div_one(a, b), "U256 floor(a·b/ONE) == mul_div_one(a,b)");
        }
    }
}

#[cfg(test)]
mod proptest_wide_math {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        #[test]
        fn add_then_sub_is_identity(ah in any::<u128>(), al in any::<u128>(), bh in any::<u128>(), bl in any::<u128>()) {
            let a = U256 { hi: ah >> 2, lo: al };
            let b = U256 { hi: bh >> 2, lo: bl };
            prop_assert_eq!(a.add(b).sub(b), a, "(a + b) − b == a");
        }

        #[test]
        fn mul_then_div_recovers_the_factor(a in any::<u128>(), b in 1u128..=u128::MAX) {
            let recovered = U256::mul(a, b).div_u128(b);
            prop_assert_eq!(recovered, U256 { hi: 0, lo: a }, "a·b / b == a exactly");
        }

        #[test]
        fn div_ceil_is_the_exact_ceiling(a in any::<u128>(), b in any::<u128>(), d in 1u128..=u128::MAX) {
            let n = U256::mul(a, b);
            let fl = n.div_u128(d);
            let ce = n.div_u128_ceil(d);
            let exact = fl.checked_mul_u128(d).map(|p| p == n).unwrap_or(false);
            if exact {
                prop_assert_eq!(ce, fl, "exact division: ceil == floor");
            } else {
                prop_assert_eq!(ce, fl.add(U256 { hi: 0, lo: 1 }), "inexact division: ceil == floor + 1");
            }
        }

        #[test]
        fn checked_mul_u128_matches_mul(a in any::<u128>(), b in any::<u128>()) {
            let lhs = U256 { hi: 0, lo: a }.checked_mul_u128(b);
            prop_assert_eq!(lhs, Some(U256::mul(a, b)));
        }

        #[test]
        fn isqrt_is_the_exact_floor(n in any::<u128>()) {
            let r = isqrt(n);
            prop_assert!(r.checked_mul(r).map(|sq| sq <= n).unwrap_or(false), "r² ≤ n");
            match (r + 1).checked_mul(r + 1) {
                Some(next_sq) => prop_assert!(n < next_sq, "n < (r+1)²"),
                None => {}
            }
        }

        #[test]
        fn mul_div_one_identity_and_ceil_gap(a in any::<u128>(), b in 0u64..=u64::MAX) {
            prop_assert_eq!(mul_div_one(a, ONE), a, "·ONE is the identity");
            let b = b as u128;
            let floor = mul_div_one(a % (u64::MAX as u128 + 1), b);
            let ceil = mul_div_one_ceil(a % (u64::MAX as u128 + 1), b);
            prop_assert!(ceil >= floor && ceil - floor <= 1, "ceil is floor or floor+1");
        }
    }
}
