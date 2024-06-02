use core::fmt::{self, Display};

use crypto_bigint::modular::MontyForm;

use crate::{csidh::csidh, limbs::LIMBS, private_key::PrivateKey, public_key::PublicKey};

/// A shared secret created with the CSIDH key exchange.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SharedSecret {
    shared_secret: MontyForm<LIMBS>,
}

impl SharedSecret {
    /// Computes a shared secret from a foreign public key and a private key.
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
