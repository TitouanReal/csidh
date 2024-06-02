use core::fmt::{self, Display};

use crate::{
    csidh::csidh, csidh_params::CsidhParams, montgomery_curve::MontgomeryCurve, private_key::PrivateKey
};

use crypto_bigint::{modular::MontyForm, Uint};

// TODO Make LIMBS auto-calculated depending on chosen params
#[cfg(target_pointer_width = "32")]
const LIMBS: usize = 16;
#[cfg(target_pointer_width = "64")]
const LIMBS: usize = 8;

/// A public key for the CSIDH key exchange.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PublicKey {
    key: MontyForm<LIMBS>,
}

impl PublicKey {
    /// Computes the public key associated with the given private key.
    pub fn from<const N: usize>(private_key: PrivateKey<N>) -> Self {
        PublicKey {
            key: csidh(
                private_key.params(),
                private_key.key(),
                MontyForm::zero(private_key.params().p()),
            ),
        }
    }

    // TODO Create API not dependant on Uint - LIMBS must be transparent to the user
    /// Constructs a `PublicKey` from the foreign public key, if the key is valid.
    pub fn new(params: CsidhParams<LIMBS>, key: Uint<LIMBS>) -> Option<Self> {
        let key = MontyForm::new(&key, params.p());
        if !MontgomeryCurve::new(params, key).is_supersingular() {
            None
        } else {
            Some(PublicKey { key })
        }
    }

    pub(crate) const fn key(&self) -> MontyForm<LIMBS> {
        self.key
    }
}

impl Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.key.retrieve())
    }
}
