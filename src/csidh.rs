use crypto_bigint::{modular::MontyForm, Uint};
use oorandom::Rand64;

use crate::{csidh_params::CsidhParams, limbs::LIMBS, montgomery_curve::MontgomeryCurve};

pub fn csidh<const N: usize>(
    params: CsidhParams<N>,
    mut path: [u32; N],
    start: MontyForm<LIMBS>,
) -> MontyForm<LIMBS> {
    let p = params.p();
    let lis = params.lis();
    let mut e = MontgomeryCurve::new(params, start);

    let mut dummies: [u32; N] = {
        let mut temp = [0; N];
        for i in 0..N {
            temp[i] = 10 - path[i];
        }
        temp
    };

    let mut k = Uint::from(4u32);

    let mut rand = Rand64::new(454_621u128);

    while !path.into_iter().all(|x| x == 0) || !dummies.into_iter().all(|x| x == 0) {
        let x = MontyForm::new(&Uint::from(rand.rand_u64()), p);

        if let Some(mut point_p) = e.lift(x) {
            point_p = point_p * k;

            let s = lis
                .iter()
                .enumerate()
                .filter(|(i, _)| path[*i] > 0 || dummies[*i] > 0);

            for (i, li) in s.clone() {
                let m = {
                    let mut temp = Uint::ONE;
                    for (_, li) in s.clone().filter(|(j, _)| *j > i) {
                        temp = temp * Uint::<LIMBS>::from(*li);
                    }
                    temp
                };

                let point_k = point_p * m;

                if !point_k.is_infinity() {
                    if path[i] > 0 {
                        let mut tau = MontyForm::one(p);
                        let mut sigma = MontyForm::zero(p);

                        for multiple in point_k.multiples(Uint::from(*li - 1)) {
                            let x = multiple.x();
                            tau *= x;
                            sigma = sigma + x - x.inv().unwrap();
                        }

                        let three = MontyForm::new(&Uint::from(3u32), p);
                        let b = tau * (e.a2() - sigma * three);

                        e = MontgomeryCurve::new(params, b);
                        path[i] -= 1;
                    } else {
                        let mut tau = MontyForm::one(p);
                        let mut sigma = MontyForm::zero(p);

                        for multiple in point_k.multiples(Uint::from(*li - 1)) {
                            let x = multiple.x();
                            tau *= x;
                            sigma = sigma + x - x.inv().unwrap();
                        }

                        let three = MontyForm::new(&Uint::from(3u32), p);
                        let _ = tau * (e.a2() - sigma * three);

                        dummies[i] -= 1;
                    }

                    if path[i] == 0 && dummies[i] == 0 {
                        k = k * Uint::<LIMBS>::from(*li);
                    }

                    break;
                }
            }
        } else {
            continue;
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
