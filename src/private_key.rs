use crypto_bigint::modular::ConstMontyParams;

use crate::csidh_params::{csidh_1024, csidh_1792, csidh_512, CsidhParams};

/// A private key for the CSIDH key exchange.
#[derive(Clone, Copy, Debug)]
pub struct PrivateKey<const LIMBS: usize, const N: usize, MOD: ConstMontyParams<LIMBS>> {
    params: CsidhParams<LIMBS, N, MOD>,
    key: [u32; N],
}

impl<const LIMBS: usize, const N: usize, MOD: ConstMontyParams<LIMBS>> PrivateKey<LIMBS, N, MOD> {
    /// Constructs a new `PrivateKey` from the given `key`.
    ///
    /// # Panics
    ///
    /// Panics if a key element is greater than 10.
    #[must_use]
    pub const fn new(params: CsidhParams<LIMBS, N, MOD>, key: [u32; N]) -> Self {
        let mut i = 0;
        while i < N {
            assert!(key[i] <= 10, "A key element must be smaller than 10");
            i += 1;
        }
        Self { params, key }
    }

    pub(crate) const fn params(&self) -> CsidhParams<LIMBS, N, MOD> {
        self.params
    }

    pub(crate) const fn key(&self) -> [u32; N] {
        self.key
    }
}

/// A helper type for const CSIDH-512 private key declaration.
pub type PrivateKeyCsidh512 = PrivateKey<{ csidh_512::LIMBS }, { csidh_512::N }, csidh_512::MOD>;

/// A helper type for const CSIDH-1024 private key declaration.
pub type PrivateKeyCsidh1024 =
    PrivateKey<{ csidh_1024::LIMBS }, { csidh_1024::N }, csidh_1024::MOD>;

/// A helper type for const CSIDH-1792 private key declaration.
pub type PrivateKeyCsidh1792 =
    PrivateKey<{ csidh_1792::LIMBS }, { csidh_1792::N }, csidh_1792::MOD>;
