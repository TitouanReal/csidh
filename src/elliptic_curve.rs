use core::ops::{Add, Mul};

use crate::csidh_params::CsidhParams;

use crypto_bigint::{
    modular::{MontyForm, MontyParams},
    ConstChoice, Uint,
};
use oorandom::Rand64;

#[cfg(target_pointer_width = "32")]
const LIMBS: usize = 16;
#[cfg(target_pointer_width = "64")]
const LIMBS: usize = 8;

#[derive(Debug, Clone, Copy)]
pub struct Point<const N: usize> {
    // TODO keep only reference?
    curve: CsidhEllipticCurve<N>,
    proj_x: MontyForm<LIMBS>,
    proj_y: MontyForm<LIMBS>,
    proj_z: MontyForm<LIMBS>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CsidhEllipticCurve<const N: usize> {
    params: CsidhParams<N>,
    a2: MontyForm<LIMBS>,
}

impl<const N: usize> Point<N> {
    const fn new_aff(
        curve: CsidhEllipticCurve<N>,
        x: MontyForm<LIMBS>,
        y: MontyForm<LIMBS>,
    ) -> Self {
        let p = curve.field_characteristic();
        Point {
            curve,
            proj_x: x,
            proj_y: y,
            proj_z: MontyForm::one(p),
        }
    }

    const fn infinity(curve: CsidhEllipticCurve<N>) -> Self {
        let p = curve.field_characteristic();
        Point {
            curve,
            proj_x: MontyForm::zero(p),
            proj_y: MontyForm::zero(p),
            proj_z: MontyForm::zero(p),
        }
    }

    pub fn is_infinity(&self) -> bool {
        self.proj_z == MontyForm::zero(self.curve.field_characteristic())
    }

    // TODO make those functions return read references and/or make them const

    pub fn x(&self) -> Option<MontyForm<LIMBS>> {
        if self == &Point::infinity(self.curve.clone()) {
            None
        } else {
            Some(self.proj_x * self.proj_z.inv().unwrap())
        }
    }

    pub fn y(&self) -> Option<MontyForm<LIMBS>> {
        if self == &Point::infinity(self.curve.clone()) {
            None
        } else {
            Some(self.proj_y * self.proj_z.inv().unwrap())
        }
    }
}

impl<const N: usize> Add for Point<N> {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        if self.curve != other.curve {
            panic!("Adding two points from different curves is not allowed")
        }

        if self.is_infinity() {
            return other;
        }
        if other.is_infinity() {
            return self;
        }

        let x1 = self.x().unwrap();
        let y1 = self.y().unwrap();
        let x2 = other.x().unwrap();
        let y2 = other.y().unwrap();
        let x3;
        let y3;

        let p = &self.curve.field_characteristic();

        if x1 == x2 && y1 == -y2 {
            return Point::infinity(self.curve.clone());
        }

        let a2 = &self.curve.a2;
        let one = MontyForm::one(p.clone());
        let two = MontyForm::new(&Uint::from(2u32), p.clone());
        let three = MontyForm::new(&Uint::from(3u32), p.clone());

        if x1 == x2 && y1 == y2 {
            let lambda_top = three * x1.square() + two * a2 * x1 + one;
            let lambda_bottom = two * y1;
            let lambda = lambda_top * lambda_bottom.inv().unwrap();

            let x3_plus = lambda.square();
            let x3_minus = a2 + two * x1;
            x3 = x3_plus - x3_minus;

            let y3_plus = lambda * x1;
            let y3_minus = lambda * x3 + y1;
            y3 = y3_plus - y3_minus;
        } else {
            let lambda_top = y2 - y1;
            let lambda_bottom = x2 - x1;
            let lambda = lambda_top * lambda_bottom.inv().unwrap();

            let x3_plus = lambda.square();
            let x3_minus = a2 + x1 + x2;
            x3 = x3_plus - x3_minus;

            let y3_plus = lambda * x1;
            let y3_minus = lambda * x3 + y1;
            y3 = y3_plus - y3_minus;
        }

        Point::new_aff(self.curve.clone(), x3, y3)
    }
}

impl<const N: usize> Mul<u64> for Point<N> {
    type Output = Self;

    fn mul(self, other: u64) -> Self {
        self * Uint::from(other)
    }
}

impl<const N: usize> Mul<Uint<LIMBS>> for Point<N> {
    type Output = Self;

    fn mul(self, other: Uint<LIMBS>) -> Self {
        let mut r = self.clone();
        let mut s = Point::infinity(self.curve.clone());
        for index in 0..other.bits() {
            let bit = other.bit(other.bits() - index - 1);
            if bit == ConstChoice::TRUE {
                s = s + r.clone();
                r = r.clone() + r;
            } else {
                r = r + s.clone();
                s = s.clone() + s;
            }
        }

        s
    }
}

impl<const N: usize> PartialEq for Point<N> {
    fn eq(&self, other: &Self) -> bool {
        let zero = MontyForm::zero(self.curve.field_characteristic());
        if self.proj_z == zero && other.proj_z == zero {
            true
        } else if self.proj_z == zero || other.proj_z == zero {
            false
        } else if self.x().unwrap() == other.x().unwrap() && self.y().unwrap() == other.y().unwrap()
        {
            true
        } else {
            false
        }
    }
}

impl<const N: usize> CsidhEllipticCurve<N> {
    pub const fn field_characteristic(&self) -> MontyParams<LIMBS> {
        self.params.p()
    }

    pub const fn a2(&self) -> MontyForm<LIMBS> {
        self.a2
    }

    pub const fn new(params: CsidhParams<N>, a: MontyForm<LIMBS>) -> Self {
        CsidhEllipticCurve { a2: a, params }
    }

    pub fn lift(&self, x: MontyForm<LIMBS>) -> Option<Point<N>> {
        // Tonelli-shanks special case
        // In csidh, p = 3 mod 4
        let x_square = x.square();
        let n = x * x_square + self.a2 * x_square + x;

        let r = n.pow(&self.params.lis_product());

        if r.square() == n {
            Some(Point::new_aff(self.clone(), x, r))
        } else {
            None
        }
    }

    pub fn random_point(&self) -> Point<N> {
        loop {
            let mut rand = Rand64::new(816958178u128);
            let x = MontyForm::new(&Uint::from(rand.rand_u64()), self.field_characteristic());
            if let Some(point) = self.lift(x) {
                return point;
            }
        }
    }

    pub fn is_supersingular(&self) -> bool {
        let point = self.random_point();
        let mut d = Uint::ONE;
        // TODO hardcode sqrt_of_p_times_4
        let sqrt_of_p_times_4 =
            self.field_characteristic().modulus().get().sqrt() * Uint::<1>::from(4u8);

        for li in self.params.lis().into_iter() {
            let mut value = Uint::from(4u32);
            // TODO hardcode the values p/li
            for li_2 in self.params.lis().into_iter() {
                if li_2 != li {
                    value = value.mul_mod(&Uint::from(li_2), &Uint::MAX);
                }
            }

            let qi = point.clone() * value;
            if (qi.clone() * li).is_infinity() {
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

#[cfg(test)]
mod tests {
    use super::*;

    const P: MontyParams<8> = CsidhParams::CSIDH_512.p();
    const E0: CsidhEllipticCurve<74> =
        CsidhEllipticCurve::new(CsidhParams::CSIDH_512, MontyForm::zero(P));

    const POINT_A: Point<74> = Point::new_aff(
        E0,
        MontyForm::new(
            &Uint::from_be_hex(
                "635ea6487c006e601469a7c3030538397a1a038bf3a45d02b60ac813ffbc5b62\
                08082059de864765636def621e70a71addf24e43ef931aaf2791ee3c89c6155a",
            ),
            P,
        ),
        MontyForm::new(
            &Uint::from_be_hex(
                "16d5e60adef890091e8c4c6b02a3f89900821e37ce31e0a56cd3f7128d1b66b9\
                cba7ca5cf1025e0e9a1dd2f014403a0ee1c203d5ee16ee46776a859264107dd9",
            ),
            P,
        ),
    );

    const POINT_B: Point<74> = Point::new_aff(
        E0,
        MontyForm::new(
            &Uint::from_be_hex(
                "306cd03ccb8c6502fbbc5df98cdcf441e521432adff69173c121c4b418fa26c6\
                3f93842b9a4a768217ddce706d7bfb2135a30dea0c9aea9e21ce0c18624b36cc",
            ),
            P,
        ),
        MontyForm::new(
            &Uint::from_be_hex(
                "1b450a0bb68902ee95d3fe7ea9779a0c54a5350a24bf4bac18e825020319eed4\
                d8b00ac493c5f8708d384229e16ddf7b258c8b18ff4209525c5f8b44d56890d1",
            ),
            P,
        ),
    );

    #[test]
    fn point_lifting() {
        let x = MontyForm::new(
            &Uint::from_be_hex(
                "454f23d6fe33c49c4fa4e1c87c785f6abfc6d97b2b7e631cc54ecfe589dc40c7\
                054fe09a40dd3bc9ccc3f49d04d34deea4345143d18854181bb2f0690eacdf2c",
            ),
            P,
        );
        let y = MontyForm::new(
            &Uint::from_be_hex(
                "2c425f4eb317b0d6fbb227a7e8cf61005a61a6ede5b2764a8fec8f0ef44c3d45\
                b34bae45c51d55a8506580e8d037ab414123b2d6b0bc77c978493960102f749e",
            ),
            P,
        );
        let point = E0.lift(x);
        assert!(point == Some(Point::new_aff(E0, x, y)));
    }

    #[test]
    fn point_addition() {
        let result = Point::new_aff(
            E0,
            MontyForm::new(
                &Uint::from_be_hex(
                    "02763bc5abec080ea31a29ede8f1794be1058bd74750b1c48969e6b72a706b0c\
                    be18b4321b1f92c751b1ccb4d86bc979964669013712bb7d0daccaeb43a8f5e4",
                ),
                P,
            ),
            MontyForm::new(
                &Uint::from_be_hex(
                    "05fe008928dd4847a428ae7c131ad74d09170ec71355ce722665f6d34b377220\
                    09b952d158ae85595b0611db72b3acb89c1e0738bd51434936d6a9b3d72aa1b7",
                ),
                P,
            ),
        );
        assert!(POINT_A + POINT_B == result);
    }

    #[test]
    fn point_doubling() {
        let result = Point::new_aff(
            E0,
            MontyForm::new(
                &Uint::from_be_hex(
                    "06943b90d5222a3d53eb510f4c2a87101b2413f8fd22f8cad1bd3a44be42d06a\
                    5c528bef417d9a41cc81b6feb56cb69ef9bc50163a2e36cabf2684430aa79f6f",
                ),
                P,
            ),
            MontyForm::new(
                &Uint::from_be_hex(
                    "1320889e47c3e5b98b6ab80e1f52f543777879b3dd2922632342c4637182da05\
                    af306f7ee3269fc96fdc50474a246ad74c37c53a4d12c5ca1697564c19e07858",
                ),
                P,
            ),
        );
        assert!(POINT_A + POINT_A == result);
    }

    #[test]
    fn point_multiplication() {
        let result = Point::new_aff(
            E0,
            MontyForm::new(
                &Uint::from_be_hex(
                    "1c69a4fadb3436939e3a9239058abf97a867d593a523fbb739c153a260516c03\
                    ee4e7d5b6133e030a0248127a73295804d7c5e5192cfacb762a7606a1514398b",
                ),
                P,
            ),
            MontyForm::new(
                &Uint::from_be_hex(
                    "500f0f727508f34264abff1086fcdf8cd7ea22c52f49515e2e81e9d08607dc1b\
                    94f440dda7b73c03e343d4de2b2db7c545ac2e58b96057888eac64de35aba24a",
                ),
                P,
            ),
        );
        assert!(POINT_A * 63 == result);
    }
}
