use crypto_bigint::{impl_modulus, modular::ConstMontyForm, Uint};

use super::CsidhParams;

#[cfg(target_pointer_width = "32")]
pub const LIMBS: usize = 32;
#[cfg(target_pointer_width = "64")]
/// Number of limbs used to store public keys and shared secrets in CSIDH-1024
pub const LIMBS: usize = 16;

/// Number of prime numbers used for CSIDH-1024
pub const N: usize = 130;

impl_modulus!(
    MOD,
    Uint<LIMBS>,
    "10cb223ae097cf1a52167028f26d8f86d0f0a110eb0ae742b20f534e663ac13de0d82f6c8fa15f6f21aa2\
    be3e1288159e4011af24ff7c76c89be864a3160c6f02f0d257646424a34623c932d5d74a5c02e918279554\
    887b195464e27f705ddda97ccd65fb43ab68a754ddd05e9766449e1a607eb0c632468597d98552f29c18b"
);

impl CsidhParams<LIMBS, N, MOD> {
    /// A proposition for CSIDH-1024.
    pub const CSIDH_1024: CsidhParams<LIMBS, N, MOD> = CsidhParams {
        lis: [
            3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83,
            89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179,
            181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271,
            277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379,
            383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479,
            487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599,
            601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701,
            709, 719, 727, 863, 947,
        ],
        p_minus_1_over_2: Uint::from_be_hex(
            "0865911d704be78d290b38147936c7c368785088758573a15907a9a7331d609ef06c17b647d0afb790d51\
            5f1f09440acf2008d7927fbe3b644df432518b06378178692bb2321251a311e4996aeba52e01748c13caaa\
            443d8caa32713fb82eeed4be66b2fda1d5b453aa6ee82f4bb3224f0d303f5863192342cbecc2a9794e0c5",
        ),
        inverse_of_4: ConstMontyForm::new(&Uint::from_be_hex(
            "0432c88eb825f3c694859c0a3c9b63e1b43c28443ac2b9d0ac83d4d3998eb04f78360bdb23e857dbc86a8\
            af8f84a2056790046bc93fdf1db226fa1928c5831bc0bc3495d9190928d188f24cb575d29700ba4609e555\
            221ec65519389fdc17776a5f33597ed0eada29d5377417a5d9912786981fac318c91a165f66154bca7063",
        )),
        sqrt_of_p_times_4: Uint::from_be_hex(
            "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
            0000000000000000000000000000000000000000001064567fe71623dd3d0453e10c2330470580e0f1f224\
            d70507fc43905ea5cc3705f413e8c164007037e08e352ae20804b82c7ef4aff3cfc5df5a41fa2c58c6fd4",
        ),
    };
}
