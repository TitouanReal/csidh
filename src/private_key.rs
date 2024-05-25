use crate::csidh_params::CsidhParams;

use core::fmt::{self, Display};

/// A private key for the CSIDH key exchange.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PrivateKey<const N: usize> {
    params: CsidhParams<N>,
    key: [u32; N],
}

impl<const N: usize> PrivateKey<N> {
    /// Constructs a new `PrivateKey` from the given `key`.
    pub const fn new(params: CsidhParams<N>, key: [u32; N]) -> Self {
        PrivateKey { params, key }
    }

    pub(crate) const fn params(&self) -> CsidhParams<N> {
        self.params
    }

    pub(crate) const fn key(&self) -> [u32; N] {
        self.key
    }
}

impl<const N: usize> Display for PrivateKey<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for i in 0..N {
            write!(f, "({}:{}), ", self.params.lis()[i], self.key[i])?;
        }
        Ok(())
    }
}
