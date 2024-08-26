use crypto_bigint::{impl_modulus, modular::ConstMontyForm, Uint};

use super::CsidhParams;

#[cfg(target_pointer_width = "32")]
pub const LIMBS: usize = 16;
#[cfg(target_pointer_width = "64")]
/// Number of limbs used to store public keys and shared secrets in CSIDH-512
pub const LIMBS: usize = 8;

/// Number of prime numbers used for CSIDH-512
pub const N: usize = 74;

impl_modulus!(
    MOD,
    Uint<LIMBS>,
    "65b48e8f740f89bffc8ab0d15e3e4c4ab42d083aedc88c425afbfcc69322c9c\
    da7aac6c567f35507516730cc1f0b4f25c2721bf457aca8351b81b90533c6c87b"
);

impl CsidhParams<LIMBS, N, MOD> {
    /// CSIDH-512 as defined in <i>
    /// <a href=https://csidh.isogeny.org/csidh-20181118.pdf>
    /// [Castryck, W., Lange, T., Martindale, C., Panny, L., Renes, J.:
    /// CSIDH: An efficient post-quantum commutative group action. In: Peyrin, T., Galbraith, S.
    /// (eds.) ASIACRYPT 2018, LNCS 11274. pp. 395–427. Springer (2018)]
    /// </a></i>.
    pub const CSIDH_512: CsidhParams<LIMBS, N, MOD> = CsidhParams {
        lis: [
            3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83,
            89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179,
            181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271,
            277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 587,
        ],
        p_minus_1_over_2: Uint::from_be_hex(
            "32da4747ba07c4dffe455868af1f26255a16841d76e446212d7dfe63499164e\
            6d3d56362b3f9aa83a8b398660f85a792e1390dfa2bd6541a8dc0dc8299e3643d",
        ),
        inverse_of_4: ConstMontyForm::new(&Uint::from_be_hex(
            "196d23a3dd03e26fff22ac34578f9312ad0b420ebb72231096beff31a4c8b27\
            369eab1b159fcd541d459cc3307c2d3c9709c86fd15eb2a0d46e06e414cf1b21f",
        )),
        sqrt_of_p_times_4: Uint::from_be_hex(
            "000000000000000000000000000000000000000000000000000000000000000\
            2856f1399d91d6592142b9541e59682cd38d0cd95f8636a5617895e71e1a20b40",
        ),
    };
}
