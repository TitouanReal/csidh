use crate::elliptic_curve::CsidhEllipticCurve;
use crate::csidh::csidh;
use crate::public_key::PublicKey;
use crate::private_key::PrivateKey;

use core::fmt::{self, Display};

use crypto_bigint::modular::MontyForm;

// TODO Make LIMBS auto-calculated depending on chosen params
#[cfg(target_pointer_width = "32")]
const LIMBS: usize = 16;
#[cfg(target_pointer_width = "64")]
const LIMBS: usize = 8;

/// A shared secret created with the CSIDH key exchange.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SharedSecret {
    shared_secret: MontyForm<LIMBS>,
}

impl SharedSecret {
    /// Creates a shared secret from a foreign public key and a private key.
    pub fn from<const N: usize>(foreign_public_key: PublicKey, private_key: PrivateKey<N>) -> Self {
        SharedSecret {
            shared_secret: csidh(
                private_key.params(),
                private_key.key(),
                foreign_public_key.key(),
            ),
        }
    }
}

impl Display for SharedSecret {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.shared_secret.retrieve())
    }
}
