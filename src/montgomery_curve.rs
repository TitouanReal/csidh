use crypto_bigint::{
    modular::{ConstMontyForm, ConstMontyParams},
    Uint,
};
use oorandom::Rand64;

use crate::{montgomery_point::MontgomeryPoint, CsidhParams};

#[derive(Debug, Clone, Copy, PartialEq)]
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

    pub fn new(params: CsidhParams<LIMBS, N, MOD>, a2: ConstMontyForm<MOD, LIMBS>) -> Self {
        let two = ConstMontyForm::new(&Uint::from_u32(2));
        let inverse_of_4 = params.inverse_of_4();
        let a24 = (a2 + two) * inverse_of_4;
        MontgomeryCurve { params, a2, a24 }
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

    pub fn random_point(&self) -> MontgomeryPoint<LIMBS, N, MOD> {
        let mut rand = Rand64::new(816958178u128);
        loop {
            let x = ConstMontyForm::new(&Uint::from(rand.rand_u64()));
            if let Some(point) = self.lift(x) {
                return point;
            }
        }
    }

    pub fn is_supersingular(&self) -> bool {
        let point = self.random_point();
        let mut d = Uint::ONE;
        let sqrt_of_p_times_4 =
            ConstMontyForm::<MOD, LIMBS>::ONE.retrieve().sqrt() * Uint::<1>::from(4u8);

        for li in self.params.lis().into_iter() {
            let mut value = Uint::from(4u32);
            for li_2 in self.params.lis().into_iter() {
                if li_2 != li {
                    value = value.mul_mod(&Uint::from(li_2), &Uint::MAX);
                }
            }

            let qi = point * value;
            if (qi * Uint::from(li)).is_infinity() {
                return false;
            }
            if qi.is_infinity() {
                d = d.mul_mod(&Uint::from(li), &Uint::MAX);
            }
            if d > sqrt_of_p_times_4 {
                return true;
            }
        }
        self.is_supersingular()
    }
}
