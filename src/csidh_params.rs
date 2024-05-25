// TODO Make LIMBS auto-calculated depending on chosen params
#[cfg(target_pointer_width = "32")]
const LIMBS: usize = 16;
#[cfg(target_pointer_width = "64")]
const LIMBS: usize = 8;

use crypto_bigint::modular::MontyParams;
use crypto_bigint::{impl_modulus, Uint};

/// Parameters of the CSIDH key exchange.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CsidhParams<const N: usize> {
    lis: [u64; N],
    lis_product: Uint<LIMBS>,
    p: MontyParams<LIMBS>,
}

impl_modulus!(PrimeCsidh512, Uint<LIMBS>, "65b48e8f740f89bffc8ab0d15e3e4c4ab42d083aedc88c425afbfcc69322c9cda7aac6c567f35507516730cc1f0b4f25c2721bf457aca8351b81b90533c6c87b");

impl CsidhParams<74> {
    /// CSIDH-512 as defined in <i>
    /// <a href=https://csidh.isogeny.org/csidh-20181118.pdf>
    /// [Castryck, W., Lange, T., Martindale, C., Panny, L., Renes, J.:
    /// CSIDH: An efficient post-quantum commutative group action. In: Peyrin, T., Galbraith, S.
    /// (eds.) ASIACRYPT 2018, LNCS 11274. pp. 395–427. Springer (2018)]
    /// </a></i>.
    pub const CSIDH_512: CsidhParams<74> = CsidhParams {
        lis: [
            3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83,
            89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179,
            181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271,
            277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 587
        ],
        lis_product: Uint::from_be_hex("196d23a3dd03e26fff22ac34578f9312ad0b420ebb72231096beff31a4c8b27369eab1b159fcd541d459cc3307c2d3c9709c86fd15eb2a0d46e06e414cf1b21f"),
        p: MontyParams::from_const_params::<PrimeCsidh512>(),
    };
}

// TODO Enable once variable number of limbs enabled
// impl_modulus!(PrimeCsidh1024, Uint<LIMBS>, "10cb223ae097cf1a52167028f26d8f86d0f0a110eb0ae742b20f534e663ac13de0d82f6c8fa15f6f21aa2be3e1288159e4011af24ff7c76c89be864a3160c6f02f0d257646424a34623c932d5d74a5c02e918279554887b195464e27f705ddda97ccd65fb43ab68a754ddd05e9766449e1a607eb0c632468597d98552f29c18b");

// impl CsidhParams<130> {
//     /// CSIDH-1024
//     pub const CSIDH_1024: CsidhParams<130> = CsidhParams::new_no_verif(
//         [
//             3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83,
//             89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179,
//             181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271,
//             277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379,
//             383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479,
//             487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599,
//             601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701,
//             709, 719, 727, 863, 947
//         ],
//         Uint::from_be_hex("432c88eb825f3c694859c0a3c9b63e1b43c28443ac2b9d0ac83d4d3998eb04f78360bdb23e857dbc86a8af8f84a2056790046bc93fdf1db226fa1928c5831bc0bc3495d9190928d188f24cb575d29700ba4609e555221ec65519389fdc17776a5f33597ed0eada29d5377417a5d9912786981fac318c91a165f66154bca7063"),
//         MontyParams::from_const_params::<PrimeCsidh1024>(),
//     );
// }

// TODO Enable once variable number of limbs enabled
// impl_modulus!(PrimeCsidh1792, Uint<LIMBS>, "c834b95a843e9915f18fa61bbaec899a64eeaa69a5fca02506be588b823f288602d1bf582cbe08dcbb99675546a301a13010d40ed23489b890015d7e1b44024e356cd78518b16005a4cceac17964448ac53435e28dc76c933d75e319c1fda37dc8c8bf7f17106def3b9048648cfa7449e65e089ae1fa3ab5c335ff012c2bd0c6e98885c18458f6ad95e8a142f951cd01806ddf63e695c7041e69dd2da6d48fc2e3a67ee40d039878aaea7abfa49b414968a285a57144a5210cbca971107497ada777973c3d3173f16f9412e3d829d25b17ab71542c1d82fcc534b72aabb11be3");

// impl CsidhParams<201> {
//     /// CSIDH-1792
//     pub const CSIDH_1792: CsidhParams<201> = CsidhParams::new_no_verif(
//         [
//             37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113,
//             127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211,
//             223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311,
//             313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419,
//             421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521,
//             523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631,
//             641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743,
//             751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859,
//             863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983,
//             991, 997, 1009, 1013, 1019, 1021, 1031, 1033, 1039, 1049, 1051, 1061, 1063, 1069,
//             1087, 1091, 1093, 1097, 1103, 1109, 1117, 1123, 1129, 1151, 1153, 1163, 1171, 1181,
//             1187, 1193, 1201, 1213, 1217, 1223, 1229, 1231, 1237, 1249, 1259, 1277, 1279, 1283,
//             1289, 1291, 1301, 1657
//         ],
//         Uint::from_be_hex("320d2e56a10fa6457c63e986eebb2266993baa9a697f280941af9622e08fca2180b46fd60b2f82372ee659d551a8c0684c043503b48d226e2400575f86d100938d5b35e1462c580169333ab05e591122b14d0d78a371db24cf5d78c6707f68df72322fdfc5c41b7bcee41219233e9d1279978226b87e8ead70cd7fc04b0af431ba62217061163dab657a2850be547340601b77d8f9a571c1079a774b69b523f0b8e99fb90340e61e2aba9eafe926d0525a28a1695c512948432f2a5c441d25eb69dde5cf0f4c5cfc5be504b8f60a7496c5eadc550b0760bf314d2dcaaaec46f9"),
//         MontyParams::from_const_params::<PrimeCsidh1792>(),
//     );
// }

impl<const N: usize> CsidhParams<N> {
    pub(crate) const fn lis(self) -> [u64; N] {
        self.lis
    }

    pub(crate) const fn lis_product(self) -> Uint<LIMBS> {
        self.lis_product
    }

    pub(crate) const fn p(self) -> MontyParams<LIMBS> {
        self.p
    }
}
