use core::fmt::{self, Display};

use crypto_bigint::{
    modular::{BernsteinYangInverter, ConstMontyForm, ConstMontyParams},
    Odd, PrecomputeInverter, Uint,
};

use crate::{csidh::csidh, private_key::PrivateKey, public_key::PublicKey};

/// A shared secret created with the CSIDH key exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SharedSecret<const LIMBS: usize, MOD: ConstMontyParams<LIMBS>> {
    shared_secret: ConstMontyForm<MOD, LIMBS>,
}

impl<const SAT_LIMBS: usize, MOD: ConstMontyParams<SAT_LIMBS>, const UNSAT_LIMBS: usize>
    SharedSecret<SAT_LIMBS, MOD>
where
    Odd<Uint<SAT_LIMBS>>: PrecomputeInverter<
        Inverter = BernsteinYangInverter<SAT_LIMBS, UNSAT_LIMBS>,
        Output = Uint<SAT_LIMBS>,
    >,
{
    /// Computes a shared secret from a foreign public key and a private key.
    #[must_use]
    pub fn from<const N: usize>(
        foreign_public_key: PublicKey<SAT_LIMBS, MOD>,
        private_key: PrivateKey<SAT_LIMBS, N, MOD>,
    ) -> Self {
        Self {
            shared_secret: csidh(
                private_key.params(),
                private_key.key(),
                foreign_public_key.key(),
            ),
        }
    }
}

impl<const LIMBS: usize, MOD: ConstMontyParams<LIMBS>> Display for SharedSecret<LIMBS, MOD> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.shared_secret.retrieve())
    }
}
