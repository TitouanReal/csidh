use crate::elliptic_curve::CsidhEllipticCurve;
use crate::csidh_params::CsidhParams;

use crypto_bigint::modular::MontyForm;
use crypto_bigint::{NonZero, Uint};
use oorandom::Rand64;

// TODO Make LIMBS auto-calculated depending on chosen params
#[cfg(target_pointer_width = "32")]
const LIMBS: usize = 16;
#[cfg(target_pointer_width = "64")]
const LIMBS: usize = 8;

pub fn csidh<const N: usize>(
    params: CsidhParams<N>,
    mut path: [i32; N],
    start: MontyForm<LIMBS>,
) -> MontyForm<LIMBS> {
    let p = params.p();
    let lis = params.lis();
    let mut e = CsidhEllipticCurve::new(params.clone(), start);

    let mut rand = Rand64::new(454_621u128);
    while !path.into_iter().all(|x| x == 0) {
        let x = MontyForm::new(&Uint::from(rand.rand_u64()), p.clone());

        if let Some(mut point) = e.lift(x) {
            let order;

            if cfg!(feature = "no_cm_order") {
                // Order calculation
                order = point.order();
            } else {
                // Remove possible factor 2 from the order of the point
                point = point * 4;
                // Order calculation
                order = point.order_not_multiple_of_2();
            }

            for (i, li) in lis.into_iter().enumerate() {
                if path[i] <= 0 {
                    continue;
                }

                // div rem
                let (div, rem) = order
                    .clone()
                    .div_rem(&NonZero::new(Uint::from(li)).unwrap());
                if rem != Uint::ZERO {
                    continue;
                }

                // Regularization ("reg")
                point = point * div;

                let mut temp = point.clone();
                let mut tau = MontyForm::one(p.clone());
                let mut sigma = MontyForm::zero(p.clone());

                // Countermeasure against variable time VeLu
                if cfg!(feature = "no_cm_velu") {
                    // Velu
                    for _ in 1..li {
                        let x = temp.x().unwrap();
                        tau = tau * x;
                        sigma = sigma + x - x.inv().unwrap();
                        temp = temp + point.clone();
                    }
                } else {
                    // Velu
                    for _ in 1..li {
                        let x = temp.x().unwrap();
                        tau = tau * x;
                        sigma = sigma + x - x.inv().unwrap();
                        temp = temp + point.clone();
                    }
                    let mut dummy_left = lis[lis.len() - 1] - li;
                    while dummy_left != 0 {
                        let mut temp2 = point.clone();
                        let mut tau2 = MontyForm::one(p.clone());
                        let mut sigma2 = MontyForm::zero(p.clone());
                        for _ in 1..li {
                            let x = temp2.x().unwrap();
                            tau2 = tau2 * x;
                            sigma2 = sigma2 + x - x.inv().unwrap();
                            temp2 = temp2 + point.clone();
                            dummy_left -= 1;
                            if dummy_left == 0 {
                                break;
                            }
                        }
                    }
                }

                let three = MontyForm::new(&Uint::from(3u32), p.clone());
                let b = tau * (e.a2() - sigma * three);
                e = CsidhEllipticCurve::new(params.clone(), b);
                path[i] -= 1;

                break;
            }
        } else {
            continue;
            // TODO construct E over Fp2
            // TODO find order of P
            // TODO construct point of good order
            // TODO find next e with VELU
        }
    }
    e.a2()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_csidh() {
        let params = CsidhParams::EXAMPLE_1;
        let p = params.p();
        let path = [
            1, 2, 5, 3, 4, 2, 3, 5, 1, 2, 0, 3, 7, 1, 3, 4, 0, 3, 1, 5, 4,
        ];
        let start = MontyForm::zero(p);
        let public_key = csidh(params, path, start);
        assert_eq!(
            public_key,
            MontyForm::new(&Uint::from_be_hex("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000032F5FA35675EEB1CABC777FAED"), p)
        );
    }
}
