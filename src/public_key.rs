use core::fmt::{self, Display};

use crypto_bigint::{
    modular::{BernsteinYangInverter, ConstMontyForm, ConstMontyParams},
    Odd, PrecomputeInverter, Uint,
};

use crate::{
    csidh::csidh, csidh_params::CsidhParams, montgomery_curve::MontgomeryCurve,
    private_key::PrivateKey,
};

/// A public key for the CSIDH key exchange.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PublicKey<const LIMBS: usize, MOD: ConstMontyParams<LIMBS>> {
    key: ConstMontyForm<MOD, LIMBS>,
}

impl<const SAT_LIMBS: usize, MOD: ConstMontyParams<SAT_LIMBS>, const UNSAT_LIMBS: usize>
    PublicKey<SAT_LIMBS, MOD>
where
    Odd<Uint<SAT_LIMBS>>: PrecomputeInverter<
        Inverter = BernsteinYangInverter<SAT_LIMBS, UNSAT_LIMBS>,
        Output = Uint<SAT_LIMBS>,
    >,
{
    /// Computes the public key associated with the given private key.
    #[must_use]
    pub fn from<const N: usize>(private_key: PrivateKey<SAT_LIMBS, N, MOD>) -> Self {
        Self {
            key: csidh(
                private_key.params(),
                private_key.key(),
                ConstMontyForm::ZERO,
            ),
        }
    }

    /// Constructs a `PublicKey` from the foreign public key, if the key is valid.
    #[must_use]
    pub fn new<const N: usize>(
        params: CsidhParams<SAT_LIMBS, N, MOD>,
        key: Uint<SAT_LIMBS>,
    ) -> Option<Self> {
        let key = ConstMontyForm::new(&key);
        if MontgomeryCurve::new(params, key).is_supersingular() {
            Some(Self { key })
        } else {
            None
        }
    }

    pub(crate) const fn key(&self) -> ConstMontyForm<MOD, SAT_LIMBS> {
        self.key
    }
}

impl<const LIMBS: usize, MOD: ConstMontyParams<LIMBS>> Display for PublicKey<LIMBS, MOD> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.key.retrieve())
    }
}
