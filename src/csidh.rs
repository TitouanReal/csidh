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
    fn csidh_easy() {
        let params = CsidhParams::CSIDH_512;
        let p = params.p();
        let path = {
            let mut temp = [0; 74];
            temp[0] = 1;
            temp
        };
        let start = MontyForm::zero(p);
        let public_key = csidh(params, path, start);
        assert_eq!(
            public_key,
            MontyForm::new(
                &Uint::from_be_hex(
                    "53BAA451F759835A01933C76BC58C0C203A9B6B02F7F086B30C3469A8452750\
                    AAECA8A4F7C26BFF43876F4510F405F4D2A006635D89A42D327D9A2E8C00BF340"
                ),
                p
            )
        );
    }

    #[test]
    fn csidh_medium() {
        let params = CsidhParams::CSIDH_512;
        let p = params.p();
        let path = {
            let mut temp = [0; 74];
            temp[0] = 1;
            temp[1] = 1;
            temp
        };
        let start = MontyForm::zero(p);
        let public_key = csidh(params, path, start);
        assert_eq!(
            public_key,
            MontyForm::new(
                &Uint::from_be_hex(
                    "64BB503A4BCA4A4CEF79A054740B11D35C2D1C5778FC05F5AEA1C4FA0CFE4C9\
                    E36198514A67F220116C0F70C5511FB4163BECD5CF7347BC2DB66306AAFE6CEF0"
                ),
                p
            )
        );
    }

    #[test]
    fn csidh_long() {
        let params = CsidhParams::CSIDH_512;
        let p = params.p();
        let path = {
            let mut temp = [0; 74];
            temp[0] = 1;
            temp[1] = 3;
            temp[73] = 1;
            temp
        };
        let start = MontyForm::zero(p);
        let public_key = csidh(params, path, start);
        assert_eq!(
            public_key,
            MontyForm::new(
                &Uint::from_be_hex(
                    "3F0D6D05BDB550AF6459BBDBC08E40338AA2D22A4E8BD6EF1DF113688D3FD23\
                    EAB8C22365A23C4702A2AAC1835B7BED06B0C8E78E5F432D6296C244812CF25B3"
                ),
                p
            )
        );
    }

    #[test]
    fn csidh_very_long() {
        let params = CsidhParams::CSIDH_512;
        let p = params.p();
        let path = [
            8, 2, 9, 3, 3, 0, 7, 2, 0, 8, 1, 9, 9, 4, 0, 10, 6, 3, 10, 7, 2, 3, 1, 4, 5, 3, 9, 10,
            9, 3, 8, 5, 1, 10, 2, 4, 2, 10, 1, 1, 10, 8, 0, 9, 1, 8, 7, 6, 10, 9, 9, 4, 10, 6, 4,
            4, 2, 3, 5, 5, 5, 3, 0, 9, 6, 9, 8, 5, 5, 9, 2, 0, 3, 6,
        ];
        let start = MontyForm::zero(p);
        let public_key = csidh(params, path, start);
        assert_eq!(
            public_key,
            MontyForm::new(
                &Uint::from_be_hex(
                    "4ABA8DC557FA0A29A38A133253A99619A4EE708BD8A23284138CF6759C06B13\
                    B7CF623502EAFC1D1F847CF42A72C8807F6E9E79B56ED4318EAC92C7E93DCA1AC"
                ),
                p
            )
        );
    }
}
