use crypto_bigint::{
    Odd, PrecomputeInverter, Uint,
    modular::{ConstMontyForm, ConstMontyParams, SafeGcdInverter},
    rand_core::CryptoRngCore,
};

use crate::{
    CsidhParams, csidh::csidh, montgomery_curve::MontgomeryCurve, private_key::PrivateKey,
    public_key::PublicKey,
};

/// A shared secret created with the CSIDH key exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SharedSecret<const LIMBS: usize, MOD: ConstMontyParams<LIMBS>> {
    shared_secret: ConstMontyForm<MOD, LIMBS>,
}

impl<const SAT_LIMBS: usize, MOD: ConstMontyParams<SAT_LIMBS>, const UNSAT_LIMBS: usize>
    SharedSecret<SAT_LIMBS, MOD>
where
    Odd<Uint<SAT_LIMBS>>: PrecomputeInverter<
            Inverter = SafeGcdInverter<SAT_LIMBS, UNSAT_LIMBS>,
            Output = Uint<SAT_LIMBS>,
        >,
{
    /// Computes a shared secret from a foreign public key and a private key.
    #[must_use]
    pub fn from<const N: usize>(
        foreign_public_key: PublicKey<SAT_LIMBS, MOD>,
        private_key: PrivateKey<SAT_LIMBS, N, MOD>,
        rng: &mut impl CryptoRngCore,
    ) -> Self {
        Self {
            shared_secret: csidh(
                private_key.params(),
                private_key.key(),
                foreign_public_key.key(),
                rng,
            ),
        }
    }

    /// Constructs a `SharedSecret` from the foreign shared secret, if the secret is valid.
    #[must_use]
    pub fn new<const N: usize>(
        params: CsidhParams<SAT_LIMBS, N, MOD>,
        shared_secret: Uint<SAT_LIMBS>,
        rng: &mut impl CryptoRngCore,
    ) -> Option<Self> {
        let shared_secret = ConstMontyForm::new(&shared_secret);
        if MontgomeryCurve::new(params, shared_secret).is_supersingular(rng) {
            Some(Self { shared_secret })
        } else {
            None
        }
    }

    ///Creates a foreign shared secret from this `SharedSecret`
    pub fn to_repr(&self) -> Uint<SAT_LIMBS> {
        return self.shared_secret.to_montgomery();
    }
}
