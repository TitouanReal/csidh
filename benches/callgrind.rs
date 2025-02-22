use crypto_bigint::{
    Odd, PrecomputeInverter, Uint,
    modular::{ConstMontyParams, SafeGcdInverter},
};
use csidh::{CsidhParams, PrivateKey, PublicKey};
use iai_callgrind::{black_box, library_benchmark, library_benchmark_group, main};
use rand::Rng;

fn private_key<const LIMBS: usize, const N: usize, MOD: ConstMontyParams<LIMBS>>(
    params: CsidhParams<LIMBS, N, MOD>,
) -> PrivateKey<LIMBS, N, MOD> {
    let mut path = [0; N];

    for element in path.iter_mut() {
        *element = rand::thread_rng().gen_range(0..=10);
    }

    PrivateKey::new(params, path)
}

#[library_benchmark]
#[bench::random(private_key(CsidhParams::CSIDH_512))]
fn public_key_1<
    const SAT_LIMBS: usize,
    const N: usize,
    MOD: ConstMontyParams<SAT_LIMBS>,
    const UNSAT_LIMBS: usize,
>(
    private_key: PrivateKey<SAT_LIMBS, N, MOD>,
) where
    Odd<Uint<SAT_LIMBS>>: PrecomputeInverter<
            Inverter = SafeGcdInverter<SAT_LIMBS, UNSAT_LIMBS>,
            Output = Uint<SAT_LIMBS>,
        >,
{
    let _ = PublicKey::from(black_box(private_key), &mut rand::thread_rng());
}

#[library_benchmark]
#[bench::random(private_key(CsidhParams::CSIDH_512))]
fn public_key_2<
    const SAT_LIMBS: usize,
    const N: usize,
    MOD: ConstMontyParams<SAT_LIMBS>,
    const UNSAT_LIMBS: usize,
>(
    private_key: PrivateKey<SAT_LIMBS, N, MOD>,
) where
    Odd<Uint<SAT_LIMBS>>: PrecomputeInverter<
            Inverter = SafeGcdInverter<SAT_LIMBS, UNSAT_LIMBS>,
            Output = Uint<SAT_LIMBS>,
        >,
{
    let _ = PublicKey::from(black_box(private_key), &mut rand::thread_rng());
}

#[library_benchmark]
#[bench::random(private_key(CsidhParams::CSIDH_512))]
fn public_key_3<
    const SAT_LIMBS: usize,
    const N: usize,
    MOD: ConstMontyParams<SAT_LIMBS>,
    const UNSAT_LIMBS: usize,
>(
    private_key: PrivateKey<SAT_LIMBS, N, MOD>,
) where
    Odd<Uint<SAT_LIMBS>>: PrecomputeInverter<
            Inverter = SafeGcdInverter<SAT_LIMBS, UNSAT_LIMBS>,
            Output = Uint<SAT_LIMBS>,
        >,
{
    let _ = PublicKey::from(black_box(private_key), &mut rand::thread_rng());
}

library_benchmark_group!(
    name = public_key_group;
    benchmarks =
        public_key_1,
        public_key_2,
        public_key_3,
);

main!(library_benchmark_groups = public_key_group);
