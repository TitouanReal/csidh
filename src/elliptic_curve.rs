use crate::csidh_params::CsidhParams;

use core::ops::{Add, Mul};

use crypto_bigint::modular::{MontyForm, MontyParams};
use crypto_bigint::{ConstChoice, NonZero, Uint};
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
        let p = &self.field_characteristic();
        // Tonelli-shanks special case
        // In csidh, p = 3 mod 4
        let x_square = x.square();
        let n = x * x_square + self.a2 * x_square + x;

        let r;

        // Countermeasure against (p+1)/4
        if cfg!(feature = "no_cm_p_plus_1_over_4") {
            // (p+1)/4 calculation
            let mut exponent: Uint<LIMBS> = Uint::ONE;

            for li in self.params.lis().into_iter() {
                exponent = exponent.mul_mod(&Uint::from(li), &p.modulus().get());
            }

            // lift exp
            r = n.pow(&exponent);
        } else {
            // lift exp
            r = n.pow(&self.params.lis_product());
        }

        // lift square
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

    #[test]
    fn test_point_lifting() {
        let params = CsidhParams::EXAMPLE_0;
        let p = params.p();
        let e = CsidhEllipticCurve::new(params, MontyForm::zero(p));

        let x = MontyForm::new(&Uint::from(193u32), p);
        let y = MontyForm::new(&Uint::from(116u32), p);
        let point = e.lift(x);
        assert!(point == Some(Point::new_aff(e.clone(), x, y)));

        let x = MontyForm::new(&Uint::from(132u32), p);
        let y = MontyForm::new(&Uint::from(48u32), p);
        let point = e.lift(x);
        assert!(point == Some(Point::new_aff(e.clone(), x, y)));

        let x = MontyForm::new(&Uint::from(7u32), p);
        let point = e.lift(x);
        assert!(point.is_none());
    }

    #[test]
    fn test_point_addition() {
        let params = CsidhParams::EXAMPLE_0;
        let p = params.p();
        let e = CsidhEllipticCurve::new(params, MontyForm::zero(p));

        let point_a = Point::new_aff(
            e.clone(),
            MontyForm::new(&Uint::from(132u32), p),
            MontyForm::new(&Uint::from(48u32), p),
        );
        let point_b = Point::new_aff(
            e.clone(),
            MontyForm::new(&Uint::from(380u32), p),
            MontyForm::new(&Uint::from(130u32), p),
        );
        let point_c = Point::new_aff(
            e.clone(),
            MontyForm::new(&Uint::from(161u32), p),
            MontyForm::new(&Uint::from(331u32), p),
        );
        assert!(point_a + point_b == point_c);

        let point_d = Point::new_aff(
            e.clone(),
            MontyForm::new(&Uint::from(74u32), p),
            MontyForm::new(&Uint::from(214u32), p),
        );
        let point_e = Point::infinity(e.clone());
        assert!(point_d.clone() + point_e.clone() == point_d);

        let point_f = Point::new_aff(
            e.clone(),
            MontyForm::new(&Uint::from(417u32), p),
            MontyForm::new(&Uint::from(165u32), p),
        );
        let point_g = Point::new_aff(
            e.clone(),
            MontyForm::new(&Uint::from(417u32), p),
            MontyForm::new(&Uint::from(254u32), p),
        );
        assert!(point_f.clone() + point_g == point_e);
    }

    #[test]
    fn test_point_doubling() {
        let params = CsidhParams::EXAMPLE_0;
        let p = params.p();
        let e = CsidhEllipticCurve::new(params, MontyForm::zero(p));

        let point_a = Point::new_aff(
            e.clone(),
            MontyForm::new(&Uint::from(74u32), p),
            MontyForm::new(&Uint::from(214u32), p),
        );
        let point_b = Point::new_aff(
            e.clone(),
            MontyForm::new(&Uint::from(139u32), p),
            MontyForm::new(&Uint::from(35u32), p),
        );
        assert!(point_a.clone() + point_a == point_b);

        let point_c = Point::new_aff(
            e.clone(),
            MontyForm::new(&Uint::from(61u32), p),
            MontyForm::new(&Uint::from(319u32), p),
        );
        let point_d = Point::new_aff(
            e.clone(),
            MontyForm::new(&Uint::from(413u32), p),
            MontyForm::new(&Uint::from(240u32), p),
        );
        assert!(point_c.clone() + point_c == point_d);

        let point_e = Point::infinity(e.clone());
        assert!(point_e.clone() + point_e.clone() == point_e);
    }

    #[test]
    fn test_point_multiplication_by_2() {
        let params = CsidhParams::EXAMPLE_0;
        let p = params.p();
        let e = CsidhEllipticCurve::new(params, MontyForm::zero(p));

        let point_a = Point::new_aff(
            e.clone(),
            MontyForm::new(&Uint::from(74u32), p),
            MontyForm::new(&Uint::from(205u32), p),
        );
        let point_b = Point::new_aff(
            e.clone(),
            MontyForm::new(&Uint::from(139u32), p),
            MontyForm::new(&Uint::from(384u32), p),
        );
        assert!(point_a.clone() * 2 == point_b);
    }

    #[test]
    fn test_point_multiplication() {
        let params = CsidhParams::EXAMPLE_0;
        let p = params.p();
        let e = CsidhEllipticCurve::new(params, MontyForm::zero(p));

        let point_a = Point::new_aff(
            e.clone(),
            MontyForm::new(&Uint::from(74u32), p),
            MontyForm::new(&Uint::from(214u32), p),
        );
        let point_b = Point::new_aff(
            e.clone(),
            MontyForm::new(&Uint::from(56u32), p),
            MontyForm::new(&Uint::from(207u32), p),
        );
        assert!(point_a * 3 == point_b);

        let point_c = Point::new_aff(
            e.clone(),
            MontyForm::new(&Uint::from(417u32), p),
            MontyForm::new(&Uint::from(165u32), p),
        );
        let point_d = Point::infinity(e.clone());
        assert!(point_c * 70 == point_d);
    }

    #[test]
    fn test_order_calculation() {
        let params = CsidhParams::EXAMPLE_0;
        let p = params.p();
        let e = CsidhEllipticCurve::new(params, MontyForm::zero(p));

        let point = Point::new_aff(
            e.clone(),
            MontyForm::new(&Uint::from(193u32), p),
            MontyForm::new(&Uint::from(116u32), p),
        );
        assert_eq!(point.order(), Uint::from(140u32));

        let point = Point::new_aff(
            e.clone(),
            MontyForm::new(&Uint::from(417u32), p),
            MontyForm::new(&Uint::from(165u32), p),
        );
        assert_eq!(point.order(), Uint::from(70u32));
    }

    #[test]
    fn test_multiplication_by_order() {
        let params = CsidhParams::EXAMPLE_0;
        let p = params.p();
        let e = CsidhEllipticCurve::new(params, MontyForm::zero(p));

        let point = Point::new_aff(
            e.clone(),
            MontyForm::new(&Uint::from(193u32), p),
            MontyForm::new(&Uint::from(116u32), p),
        );
        assert_eq!((point.clone() * point.order()).proj_z, MontyForm::zero(p));
    }
}
