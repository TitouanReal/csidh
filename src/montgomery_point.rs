use core::ops::Mul;

use crypto_bigint::{modular::MontyForm, ConstChoice, Uint};

use crate::{limbs::LIMBS, montgomery_curve::MontgomeryCurve};

pub struct PointMultiples<const N: usize> {
    n_times_p: MontgomeryPoint<N>,
    p: MontgomeryPoint<N>,
    n_minus_1_times_p: MontgomeryPoint<N>,
    left: Uint<LIMBS>,
}

impl<const N: usize> PointMultiples<N> {
    fn new(p: MontgomeryPoint<N>, d: Uint<LIMBS>) -> Self {
        PointMultiples {
            n_times_p: MontgomeryPoint::infinity(p.curve),
            p,
            n_minus_1_times_p: MontgomeryPoint::infinity(p.curve),
            left: d,
        }
    }
}

impl<const N: usize> Iterator for PointMultiples<N> {
    type Item = MontgomeryPoint<N>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.left == Uint::ZERO {
            return None;
        }

        if self.n_times_p.is_infinity() {
            self.n_times_p = self.p;
            self.left = self.left - Uint::ONE;
            return Some(self.p);
        }

        let x1 = self.n_times_p.X;
        let x2 = self.p.X;

        let n_plus_1_times_p = if x1 == x2 {
            self.p.double()
        } else {
            self.n_times_p
                .differential_add(self.p, self.n_minus_1_times_p)
        };

        self.n_minus_1_times_p = self.n_times_p;
        self.n_times_p = n_plus_1_times_p;
        self.left = self.left - Uint::ONE;
        Some(n_plus_1_times_p)
    }
}

#[allow(non_snake_case)]
#[derive(Debug, Clone, Copy)]
pub struct MontgomeryPoint<const N: usize> {
    curve: MontgomeryCurve<N>,
    X: MontyForm<LIMBS>,
    Z: MontyForm<LIMBS>,
}

impl<const N: usize> MontgomeryPoint<N> {
    #[allow(non_snake_case)]
    pub const fn new(curve: MontgomeryCurve<N>, X: MontyForm<LIMBS>) -> Self {
        let p = curve.field_characteristic();
        MontgomeryPoint {
            curve,
            X,
            Z: MontyForm::one(p),
        }
    }

    const fn infinity(curve: MontgomeryCurve<N>) -> Self {
        let p = curve.field_characteristic();
        MontgomeryPoint {
            curve,
            X: MontyForm::one(p),
            Z: MontyForm::zero(p),
        }
    }

    pub fn is_infinity(&self) -> bool {
        self.Z == MontyForm::zero(self.curve.field_characteristic())
    }

    pub fn x(&self) -> MontyForm<LIMBS> {
        self.X * self.Z.inv().unwrap()
    }

    fn differential_add(
        &self,
        other: MontgomeryPoint<N>,
        self_minus_other: MontgomeryPoint<N>,
    ) -> Self {
        let x1 = self.X;
        let z1 = self.Z;
        let x2 = other.X;
        let z2 = other.Z;
        let x3 = self_minus_other.X;
        let z3 = self_minus_other.Z;

        let a = x2 + z2;
        let b = x2 - z2;
        let c = x1 + z1;
        let d = x1 - z1;
        let da = d * a;
        let cb = c * b;
        let x5 = z3 * (da + cb).square();
        let z5 = x3 * (da - cb).square();

        Self {
            curve: self.curve,
            X: x5,
            Z: z5,
        }
    }

    fn double(&self) -> Self {
        let x1 = self.X;
        let z1 = self.Z;

        let a24 = self.curve.a24();

        let a = x1 + z1;
        let aa = a.square();
        let b = x1 - z1;
        let bb = b.square();
        let c = aa - bb;
        let x3 = aa * bb;
        let z3 = c * (bb + a24 * c);

        Self {
            curve: self.curve,
            X: x3,
            Z: z3,
        }
    }

    pub fn multiples(self, d: Uint<LIMBS>) -> PointMultiples<N> {
        PointMultiples::new(self, d)
    }
}

impl<const N: usize> PartialEq for MontgomeryPoint<N> {
    fn eq(&self, other: &Self) -> bool {
        let zero = MontyForm::zero(self.curve.field_characteristic());
        if self.Z == zero && other.Z == zero {
            true
        } else if self.Z == zero || other.Z == zero {
            false
        } else {
            self.X * other.Z == self.Z * other.X
        }
    }
}

impl<const N: usize> Mul<Uint<LIMBS>> for MontgomeryPoint<N> {
    type Output = Self;

    fn mul(self, other: Uint<LIMBS>) -> Self {
        let mut x0 = self;
        let mut x1 = self.double();

        for index in (0..other.bits() - 1).rev() {
            let bit = other.bit(index);
            if bit == ConstChoice::FALSE {
                x1 = x1.differential_add(x0, self);
                x0 = x0.double();
            } else {
                x0 = x1.differential_add(x0, self);
                x1 = x1.double();
            }
        }

        x0
    }
}

#[cfg(test)]
mod tests {
    use crypto_bigint::{modular::MontyParams, Uint};

    use crate::CsidhParams;

    use super::*;

    #[test]
    fn multiples() {
        let p: MontyParams<8> = CsidhParams::CSIDH_512.p();
        let e0: MontgomeryCurve<74> =
            MontgomeryCurve::new(CsidhParams::CSIDH_512, MontyForm::zero(p));

        let point_a: MontgomeryPoint<74> = MontgomeryPoint::new(
            e0,
            MontyForm::new(
                &Uint::from_be_hex(
                    "635ea6487c006e601469a7c3030538397a1a038bf3a45d02b60ac813ffbc5b62\
                    08082059de864765636def621e70a71addf24e43ef931aaf2791ee3c89c6155a",
                ),
                p,
            ),
        );
        let point_a_times_2: MontgomeryPoint<74> = MontgomeryPoint::new(
            e0,
            MontyForm::new(
                &Uint::from_be_hex(
                    "06943b90d5222a3d53eb510f4c2a87101b2413f8fd22f8cad1bd3a44be42d06a\
                    5c528bef417d9a41cc81b6feb56cb69ef9bc50163a2e36cabf2684430aa79f6f",
                ),
                p,
            ),
        );
        let point_a_times_3: MontgomeryPoint<74> = MontgomeryPoint::new(
            e0,
            MontyForm::new(
                &Uint::from_be_hex(
                    "56227716288d568bcdf9022b3cbd0f5c3beea951cfe95a82050fa9fc8d9d9941\
                    9765dcd54a0feaa21527a13d69f5d19d7d7d9b32fcf4032a3d632736d0c1a6cd",
                ),
                p,
            ),
        );
        let point_a_times_4: MontgomeryPoint<74> = MontgomeryPoint::new(
            e0,
            MontyForm::new(
                &Uint::from_be_hex(
                    "0ac1132970689f6ec5e1b5c1103fe67813355ae1ccdcc75d5c44a50f76287e62\
                    086eef0fef12a1f905be1fa226dab017d22000dd2d3e7bac1f8a54876cb55f75",
                ),
                p,
            ),
        );
        let point_a_times_237: MontgomeryPoint<74> = MontgomeryPoint::new(
            e0,
            MontyForm::new(
                &Uint::from_be_hex(
                    "3af8740999e0b6f0d7f39593b514c9529fc4e5d393ac8907f34f9f34d646a228\
                    d9b02f85d7308bf7253058c3d957a8f99eaf97c08763b29ed48df6e918c1f1f3",
                ),
                p,
            ),
        );

        let multiples = [point_a, point_a_times_2, point_a_times_3, point_a_times_4];
        for (i, p) in point_a.multiples(Uint::from(4u32)).enumerate() {
            assert_eq!(p, multiples[i]);
        }
        assert_eq!(
            point_a_times_237,
            point_a.multiples(Uint::from(237u32)).last().unwrap()
        );
    }

    #[test]
    fn multiplication() {
        let p: MontyParams<8> = CsidhParams::CSIDH_512.p();
        let e0: MontgomeryCurve<74> =
            MontgomeryCurve::new(CsidhParams::CSIDH_512, MontyForm::zero(p));

        let point_a: MontgomeryPoint<74> = MontgomeryPoint::new(
            e0,
            MontyForm::new(
                &Uint::from_be_hex(
                    "635ea6487c006e601469a7c3030538397a1a038bf3a45d02b60ac813ffbc5b62\
                    08082059de864765636def621e70a71addf24e43ef931aaf2791ee3c89c6155a",
                ),
                p,
            ),
        );
        let point_a_times_2: MontgomeryPoint<74> = MontgomeryPoint::new(
            e0,
            MontyForm::new(
                &Uint::from_be_hex(
                    "06943b90d5222a3d53eb510f4c2a87101b2413f8fd22f8cad1bd3a44be42d06a\
                    5c528bef417d9a41cc81b6feb56cb69ef9bc50163a2e36cabf2684430aa79f6f",
                ),
                p,
            ),
        );
        let point_a_times_4: MontgomeryPoint<74> = MontgomeryPoint::new(
            e0,
            MontyForm::new(
                &Uint::from_be_hex(
                    "0ac1132970689f6ec5e1b5c1103fe67813355ae1ccdcc75d5c44a50f76287e62\
                    086eef0fef12a1f905be1fa226dab017d22000dd2d3e7bac1f8a54876cb55f75",
                ),
                p,
            ),
        );
        let point_a_times_237: MontgomeryPoint<74> = MontgomeryPoint::new(
            e0,
            MontyForm::new(
                &Uint::from_be_hex(
                    "3af8740999e0b6f0d7f39593b514c9529fc4e5d393ac8907f34f9f34d646a228\
                    d9b02f85d7308bf7253058c3d957a8f99eaf97c08763b29ed48df6e918c1f1f3",
                ),
                p,
            ),
        );

        assert!(point_a * Uint::from(2u32) == point_a_times_2);
        assert!(point_a * Uint::from(4u32) == point_a_times_4);
        assert!(point_a * Uint::from(237u32) == point_a_times_237);
    }
}
