use core::fmt::{self, Display};

use crypto_bigint::modular::ConstMontyParams;

use crate::csidh_params::CsidhParams;

/// A private key for the CSIDH key exchange.
#[derive(Clone, Copy, Debug, PartialEq)]
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
    pub const fn new(params: CsidhParams<LIMBS, N, MOD>, key: [u32; N]) -> Self {
        let mut i = 0;
        while i < N {
            if key[i] > 10 {
                panic!("A key element is greater than 10");
            }
            i += 1;
        }
        PrivateKey { params, key }
    }

    pub(crate) const fn params(&self) -> CsidhParams<LIMBS, N, MOD> {
        self.params
    }

    pub(crate) const fn key(&self) -> [u32; N] {
        self.key
    }
}

impl<const LIMBS: usize, const N: usize, MOD: ConstMontyParams<LIMBS>> Display
    for PrivateKey<LIMBS, N, MOD>
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for i in 0..N {
            write!(f, "({}:{}), ", self.params.lis()[i], self.key[i])?;
        }
        Ok(())
    }
}
