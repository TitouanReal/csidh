use crypto_bigint::{
    Odd, PrecomputeInverter, Random, Uint,
    modular::{ConstMontyForm, ConstMontyParams, SafeGcdInverter},
    rand_core::CryptoRngCore,
};

use crate::{
    csidh_params::CsidhParams, montgomery_curve::MontgomeryCurve, montgomery_point::MontgomeryPoint,
};

pub fn csidh<
    const SAT_LIMBS: usize,
    const N: usize,
    MOD: ConstMontyParams<SAT_LIMBS>,
    const UNSAT_LIMBS: usize,
>(
    params: CsidhParams<SAT_LIMBS, N, MOD>,
    mut path: [u32; N],
    start: ConstMontyForm<MOD, SAT_LIMBS>,
    rng: &mut impl CryptoRngCore,
) -> ConstMontyForm<MOD, SAT_LIMBS>
where
    Odd<Uint<SAT_LIMBS>>: PrecomputeInverter<
            Inverter = SafeGcdInverter<SAT_LIMBS, UNSAT_LIMBS>,
            Output = Uint<SAT_LIMBS>,
        >,
{
    let lis = params.lis();
    let mut curve = MontgomeryCurve::new(params, start);

    let mut dummies: [u32; N] = {
        let mut temp = [0; N];
        for i in 0..N {
            temp[i] = 10 - path[i];
        }
        temp
    };

    let mut k = Uint::from(4u32);

    while !path.into_iter().all(|x| x == 0) || !dummies.into_iter().all(|x| x == 0) {
        let x = ConstMontyForm::new(&Uint::random(rng));

        if let Some(mut point_p) = curve.lift(x) {
            point_p = point_p * k;

            let path_copy = path;
            let dummies_copy: [u32; N] = dummies;

            let s = lis
                .iter()
                .enumerate()
                .filter(|(i, _)| path_copy[*i] > 0 || dummies_copy[*i] > 0);

            for (i, li) in s.clone() {
                let m = {
                    let mut temp = Uint::ONE;
                    for (_, li) in s.clone().filter(|(j, _)| *j > i) {
                        temp *= Uint::<SAT_LIMBS>::from(*li);
                    }
                    temp
                };

                let point_k = point_p * m;

                if !point_k.is_infinity() {
                    let mut tau = ConstMontyForm::ONE;
                    let mut sigma = ConstMontyForm::ZERO;

                    for multiple in point_k.multiples(Uint::from(*li - 1)) {
                        let x = multiple.x();
                        tau *= x;
                        sigma = sigma + x - x.inv().unwrap();
                    }

                    let three = ConstMontyForm::new(&Uint::from(3u32));

                    if path[i] > 0 {
                        let b = tau * (curve.a2() - sigma * three);

                        curve = MontgomeryCurve::new(params, b);
                        point_p = {
                            let x = point_p.X();
                            let z = point_p.Z();
                            let x_plus_z = x + z;
                            let x_minus_z = x - z;

                            let mut temp_x = ConstMontyForm::ONE;
                            let mut temp_z = ConstMontyForm::ONE;
                            for multiple in point_k.multiples(Uint::from(li / 2)) {
                                let xi = multiple.X();
                                let zi = multiple.Z();

                                let a = x_minus_z * (xi + zi);
                                let b = x_plus_z * (xi - zi);

                                temp_x *= a + b;
                                temp_z *= a - b;
                            }

                            let x_prime = x * temp_x.square();
                            let z_prime = z * temp_z.square();

                            MontgomeryPoint::new(curve, x_prime, z_prime)
                        };
                        path[i] -= 1;
                    } else {
                        let _ = tau * (curve.a2() - sigma * three);

                        point_p = point_p * Uint::from(*li);
                        dummies[i] -= 1;
                    }

                    if path[i] == 0 && dummies[i] == 0 {
                        k *= Uint::<SAT_LIMBS>::from(*li);
                    }
                }
            }
        }
    }
    curve.a2()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csidh_512_1() {
        let params = CsidhParams::CSIDH_512;
        let path = {
            let mut temp = [0; 74];
            temp[0] = 1;
            temp
        };
        let start = ConstMontyForm::ZERO;
        let public_key = csidh(params, path, start, &mut rand::thread_rng());
        assert_eq!(
            public_key,
            ConstMontyForm::new(&Uint::from_be_hex(
                "53BAA451F759835A01933C76BC58C0C203A9B6B02F7F086B30C3469A8452750\
                AAECA8A4F7C26BFF43876F4510F405F4D2A006635D89A42D327D9A2E8C00BF340"
            ))
        );
    }

    #[test]
    fn csidh_512_2() {
        let params = CsidhParams::CSIDH_512;
        let path = {
            let mut temp = [0; 74];
            temp[0] = 1;
            temp[1] = 1;
            temp
        };
        let start = ConstMontyForm::ZERO;
        let public_key = csidh(params, path, start, &mut rand::thread_rng());
        assert_eq!(
            public_key,
            ConstMontyForm::new(&Uint::from_be_hex(
                "64BB503A4BCA4A4CEF79A054740B11D35C2D1C5778FC05F5AEA1C4FA0CFE4C9\
                E36198514A67F220116C0F70C5511FB4163BECD5CF7347BC2DB66306AAFE6CEF0"
            ))
        );
    }

    #[test]
    fn csidh_512_3() {
        let params = CsidhParams::CSIDH_512;
        let path = {
            let mut temp = [0; 74];
            temp[0] = 1;
            temp[1] = 3;
            temp[73] = 1;
            temp
        };
        let start = ConstMontyForm::ZERO;
        let public_key = csidh(params, path, start, &mut rand::thread_rng());
        assert_eq!(
            public_key,
            ConstMontyForm::new(&Uint::from_be_hex(
                "3F0D6D05BDB550AF6459BBDBC08E40338AA2D22A4E8BD6EF1DF113688D3FD23\
                EAB8C22365A23C4702A2AAC1835B7BED06B0C8E78E5F432D6296C244812CF25B3"
            ))
        );
    }

    #[test]
    fn csidh_512_4() {
        let params = CsidhParams::CSIDH_512;
        let path = [
            8, 2, 9, 3, 3, 0, 7, 2, 0, 8, 1, 9, 9, 4, 0, 10, 6, 3, 10, 7, 2, 3, 1, 4, 5, 3, 9, 10,
            9, 3, 8, 5, 1, 10, 2, 4, 2, 10, 1, 1, 10, 8, 0, 9, 1, 8, 7, 6, 10, 9, 9, 4, 10, 6, 4,
            4, 2, 3, 5, 5, 5, 3, 0, 9, 6, 9, 8, 5, 5, 9, 2, 0, 3, 6,
        ];
        let start = ConstMontyForm::ZERO;
        let public_key = csidh(params, path, start, &mut rand::thread_rng());
        assert_eq!(
            public_key,
            ConstMontyForm::new(&Uint::from_be_hex(
                "4ABA8DC557FA0A29A38A133253A99619A4EE708BD8A23284138CF6759C06B13\
                B7CF623502EAFC1D1F847CF42A72C8807F6E9E79B56ED4318EAC92C7E93DCA1AC"
            ))
        );
    }

    #[test]
    fn csidh_1024_1() {
        let params = CsidhParams::CSIDH_1024;
        let path = [
            10, 2, 1, 10, 5, 2, 0, 9, 7, 7, 0, 0, 2, 9, 0, 5, 3, 7, 8, 2, 6, 5, 5, 8, 8, 1, 10, 5,
            6, 2, 2, 1, 5, 5, 3, 0, 9, 10, 9, 5, 6, 7, 9, 3, 9, 5, 0, 7, 2, 1, 10, 7, 3, 9, 2, 8,
            1, 4, 4, 3, 3, 5, 10, 10, 8, 10, 5, 0, 3, 6, 7, 3, 3, 10, 8, 10, 3, 4, 10, 3, 2, 1, 3,
            8, 9, 7, 8, 3, 8, 9, 5, 4, 2, 0, 2, 3, 5, 10, 3, 9, 7, 4, 2, 2, 0, 9, 4, 2, 5, 3, 2, 6,
            6, 10, 10, 6, 0, 5, 7, 4, 8, 10, 3, 6, 7, 2, 6, 4, 1, 8,
        ];
        let start = ConstMontyForm::ZERO;
        let public_key = csidh(params, path, start, &mut rand::thread_rng());
        assert_eq!(
            public_key,
            ConstMontyForm::new(&Uint::from_be_hex(
                "0DB99E61C9C9E2C7F6B55574C2887BA557664416C65E0B5DFB8B8391FF74666\
                1746FAE9967AE4A3AEE905E5C320A398F8E9987B66A9EB91BD1D749A0916C590\
                80E7EC227B15E0F5A9BDFC41AE7927AA8A67D3289AE45FE06877D124420337CE\
                90F6C3754186136684A533246E4A95BBB4C138342766729E79E7482E7AF355B31"
            ))
        );
    }

    #[test]
    fn csidh_1024_2() {
        let params = CsidhParams::CSIDH_1024;
        let path = [
            7, 4, 3, 4, 9, 1, 3, 4, 6, 4, 8, 5, 6, 10, 9, 10, 6, 4, 10, 6, 6, 3, 10, 9, 2, 0, 5, 6,
            5, 0, 2, 4, 5, 3, 1, 2, 0, 3, 5, 0, 5, 6, 10, 9, 4, 0, 6, 4, 8, 7, 8, 4, 1, 3, 2, 1, 9,
            2, 9, 4, 3, 6, 0, 10, 0, 6, 1, 5, 6, 8, 0, 1, 8, 4, 3, 2, 6, 8, 2, 5, 2, 9, 0, 3, 5, 7,
            7, 8, 7, 7, 0, 4, 7, 6, 2, 6, 7, 6, 1, 8, 6, 9, 6, 3, 6, 1, 5, 8, 4, 4, 7, 3, 8, 10, 0,
            5, 2, 5, 2, 5, 9, 10, 0, 4, 4, 9, 6, 9, 10, 9,
        ];
        let start = ConstMontyForm::new(&Uint::from_be_hex(
            "0DB99E61C9C9E2C7F6B55574C2887BA557664416C65E0B5DFB8B8391FF746661746FAE9967AE4A3AEE905\
            E5C320A398F8E9987B66A9EB91BD1D749A0916C59080E7EC227B15E0F5A9BDFC41AE7927AA8A67D3289AE4\
            5FE06877D124420337CE90F6C3754186136684A533246E4A95BBB4C138342766729E79E7482E7AF355B31",
        ));
        let public_key = csidh(params, path, start, &mut rand::thread_rng());
        assert_eq!(
            public_key,
            ConstMontyForm::new(&Uint::from_be_hex(
                "0D63151E8CAE91D94BBB6E594DB8D252539CA51E37FE5E2999777F81109E884\
                C89E5E68527B42BEEEF685EBB7FA540B5E6150B41F59619AA054AC982DF05C74\
                5F5879BAF68C38C5B381591AC6767F8130B47A2B42DEA1466B1B065F75600C94\
                9401E2BF6ED8F56EA203C7CD7D298E4047E7E6DF97904A0D5EB265D8BF5B6DE9C"
            ))
        );
    }

    #[test]
    fn csidh_1792_1() {
        let params = CsidhParams::CSIDH_1792;
        let path = [
            5, 4, 0, 2, 1, 2, 1, 9, 4, 7, 6, 2, 10, 6, 8, 6, 7, 7, 1, 4, 1, 0, 9, 9, 8, 3, 4, 10,
            4, 9, 1, 3, 7, 5, 5, 10, 3, 3, 2, 3, 9, 5, 4, 2, 8, 8, 10, 2, 8, 0, 2, 6, 4, 7, 0, 2,
            5, 3, 3, 8, 8, 7, 4, 4, 4, 5, 3, 5, 7, 4, 0, 5, 6, 3, 8, 2, 9, 10, 2, 7, 7, 7, 6, 9, 7,
            4, 4, 1, 7, 7, 2, 9, 2, 9, 4, 2, 1, 0, 5, 1, 7, 9, 10, 7, 1, 7, 3, 8, 2, 3, 2, 3, 6, 7,
            7, 3, 1, 0, 7, 2, 4, 3, 6, 0, 7, 0, 4, 6, 2, 6, 5, 6, 5, 3, 8, 7, 2, 9, 0, 0, 8, 0, 1,
            1, 10, 6, 1, 9, 4, 9, 6, 2, 6, 2, 4, 6, 2, 10, 3, 10, 2, 4, 3, 6, 1, 4, 3, 5, 5, 10, 7,
            3, 5, 2, 4, 5, 7, 5, 5, 0, 3, 0, 2, 0, 3, 7, 1, 6, 6, 8, 9, 6, 7, 2, 6, 0, 3, 10, 9, 9,
            10,
        ];
        let start = ConstMontyForm::ZERO;
        let public_key = csidh(params, path, start, &mut rand::thread_rng());
        assert_eq!(
            public_key,
            ConstMontyForm::new(&Uint::from_be_hex(
                "420A7CFAE08A74B5EFA6D9FEDBE6B0B96E103FD2A4FCAE8E0D5130F51DCA81AD6570D76793\
                528E46783122A8FE4C126FF46C3385685FD841168A2297E582B8BF8CDAA8CA3A99096CB7835\
                3249917D9C9E3D2D42B298B9D50D4969B48798C74534EF2E4880E4443B489E31CA821EC9AC8\
                C0332688263E20DF82E072C8D0D10135F3AA586A2D85C25F19A328AEFD3449AEF76F882900E\
                3CF149FFBBD294FDF411AE089994B90A6EE602B837E1369AF32AA5F7C1A96A2A8262EC69CAC\
                D24DEFE873D0751CD402534514644D1DF93D5D178B41F118E34BEF52F39FC345784DD54479"
            ))
        );
    }
}
