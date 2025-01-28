use crypto_bigint::{
    modular::{ConstMontyForm, ConstMontyParams},
    rand_core::CryptoRngCore,
    Random, Uint,
};

use crate::{montgomery_point::MontgomeryPoint, CsidhParams};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MontgomeryCurve<const LIMBS: usize, const N: usize, MOD: ConstMontyParams<LIMBS>> {
    params: CsidhParams<LIMBS, N, MOD>,
    a2: ConstMontyForm<MOD, LIMBS>,
    a24: ConstMontyForm<MOD, LIMBS>,
}

impl<const LIMBS: usize, const N: usize, MOD: ConstMontyParams<LIMBS>>
    MontgomeryCurve<LIMBS, N, MOD>
{
    pub const fn a2(&self) -> ConstMontyForm<MOD, LIMBS> {
        self.a2
    }

    pub const fn a24(&self) -> ConstMontyForm<MOD, LIMBS> {
        self.a24
    }

    pub const fn new(params: CsidhParams<LIMBS, N, MOD>, a2: ConstMontyForm<MOD, LIMBS>) -> Self {
        let two = ConstMontyForm::new(&Uint::from_u32(2));
        let inverse_of_4 = params.inverse_of_4();
        // TODO use operators once feature(const_trait_impl) is stabilized
        let a24 = (a2.add(&two)).mul(&inverse_of_4);
        Self { params, a2, a24 }
    }

    pub fn lift(&self, x: ConstMontyForm<MOD, LIMBS>) -> Option<MontgomeryPoint<LIMBS, N, MOD>> {
        let x_square = x.square();
        let n = x * x_square + self.a2 * x_square + x;
        if n.pow(&self.params.p_minus_1_over_2()) == ConstMontyForm::ONE {
            Some(MontgomeryPoint::new_reduced(*self, x))
        } else {
            None
        }
    }

    pub fn random_point(&self, rng: &mut impl CryptoRngCore) -> MontgomeryPoint<LIMBS, N, MOD> {
        loop {
            let x = ConstMontyForm::new(&Uint::random(rng));
            if let Some(point) = self.lift(x) {
                return point;
            }
        }
    }

    pub fn is_supersingular(&self, rng: &mut impl CryptoRngCore) -> bool {
        let point = self.random_point(rng);
        let mut d = Uint::<LIMBS>::ONE;
        let sqrt_of_p_times_4 = self.params.sqrt_of_p_times_4();

        for li in self.params.lis() {
            let mut value = Uint::from(4u32);
            for li_2 in self.params.lis() {
                if li_2 != li {
                    value = value.wrapping_mul(&Uint::<1>::from(li_2));
                }
            }

            let qi = point * value;
            if !(qi * Uint::from(li)).is_infinity() {
                return false;
            }
            if !qi.is_infinity() {
                d = d.wrapping_mul(&Uint::<1>::from(li));
            }
            if d > sqrt_of_p_times_4 {
                return true;
            }
        }
        self.is_supersingular(rng)
    }
}
