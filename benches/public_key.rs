use criterion::{criterion_group, criterion_main, Criterion};
use csidh::{CsidhParams, PrivateKey, PublicKey};
use rand::Rng;

pub fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("Public key");
    group.sample_size(10);

    const NUMBER_OF_KEYS: usize = 10;

    let params = CsidhParams::CSIDH_512;
    let mut private_keys = [PrivateKey::new(params, [0; 74]); NUMBER_OF_KEYS];

    for i in 0..NUMBER_OF_KEYS {
        let mut path = [0; 74];
        for j in 0..74 {
            path[j] = rand::thread_rng().gen_range(0..=10);
        }
        private_keys[i] = PrivateKey::new(params, path);
    }

    for (i, private_key) in private_keys.into_iter().enumerate() {
        group.bench_with_input(
            format!("{}", i),
            &private_key,
            |b, &private_key| {
                b.iter(|| PublicKey::from(private_key))
            },
        );
    }
    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
