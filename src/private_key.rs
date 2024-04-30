use crate::csidh_params::CsidhParams;

use core::fmt::{self, Display};

/// A private key for the CSIDH key exchange.
#[derive(Debug, Clone, PartialEq)]
pub struct PrivateKey<const N: usize> {
    params: CsidhParams<N>,
    key: [i32; N],
}

impl<const N: usize> PrivateKey<N> {
    /// Creates a private key from a given path.
    pub const fn new(params: CsidhParams<N>, key: [i32; N]) -> Self {
        // TODO remove this once negative paths are implemented
        let mut i = 0;
        while i < N {
            if key[i] < 0 {
                panic!("Negative paths are unsupported as of now");
            }
            i += 1;
        }
        PrivateKey { params, key }
    }

    /// Returns the inner params of the key
    pub const fn params(&self) -> CsidhParams<N> {
        self.params
    }

    /// Returns the inner value of the key
    pub const fn key(&self) -> [i32; N] {
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
