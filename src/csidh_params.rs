use crypto_bigint::{
    impl_modulus,
    modular::{ConstMontyForm, ConstMontyParams},
    Uint,
};

/// Parameters of the CSIDH key exchange.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CsidhParams<const LIMBS: usize, const N: usize, MOD: ConstMontyParams<LIMBS>> {
    lis: [u64; N],
    p_minus_1_over_2: Uint<LIMBS>,
    inverse_of_4: ConstMontyForm<MOD, LIMBS>,
    sqrt_of_p_times_4: Uint<LIMBS>,
}

#[cfg(target_pointer_width = "32")]
pub const LIMBS_512: usize = 16;
#[cfg(target_pointer_width = "64")]
pub const LIMBS_512: usize = 8;

impl_modulus!(
    PrimeCsidh512,
    Uint<LIMBS_512>,
    "65b48e8f740f89bffc8ab0d15e3e4c4ab42d083aedc88c425afbfcc69322c9c\
    da7aac6c567f35507516730cc1f0b4f25c2721bf457aca8351b81b90533c6c87b"
);

impl CsidhParams<LIMBS_512, 74, PrimeCsidh512> {
    /// CSIDH-512 as defined in <i>
    /// <a href=https://csidh.isogeny.org/csidh-20181118.pdf>
    /// [Castryck, W., Lange, T., Martindale, C., Panny, L., Renes, J.:
    /// CSIDH: An efficient post-quantum commutative group action. In: Peyrin, T., Galbraith, S.
    /// (eds.) ASIACRYPT 2018, LNCS 11274. pp. 395–427. Springer (2018)]
    /// </a></i>.
    pub const CSIDH_512: CsidhParams<LIMBS_512, 74, PrimeCsidh512> = CsidhParams {
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

#[cfg(target_pointer_width = "32")]
pub const LIMBS_1024: usize = 32;
#[cfg(target_pointer_width = "64")]
pub const LIMBS_1024: usize = 16;

impl_modulus!(
    PrimeCsidh1024,
    Uint<LIMBS_1024>,
    "10cb223ae097cf1a52167028f26d8f86d0f0a110eb0ae742b20f534e663ac13de0d82f6c8fa15f6f21aa2\
    be3e1288159e4011af24ff7c76c89be864a3160c6f02f0d257646424a34623c932d5d74a5c02e918279554\
    887b195464e27f705ddda97ccd65fb43ab68a754ddd05e9766449e1a607eb0c632468597d98552f29c18b"
);

impl CsidhParams<LIMBS_1024, 130, PrimeCsidh1024> {
    /// A proposition for CSIDH-1024.
    pub const CSIDH_1024: CsidhParams<LIMBS_1024, 130, PrimeCsidh1024> = CsidhParams {
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

#[cfg(target_pointer_width = "32")]
pub const LIMBS_1792: usize = 56;
#[cfg(target_pointer_width = "64")]
pub const LIMBS_1792: usize = 28;

impl_modulus!(
    PrimeCsidh1792,
    Uint<LIMBS_1792>,
    "c834b95a843e9915f18fa61bbaec899a64eeaa69a5fca02506be588b823f288602d1bf582cbe08dcbb9967554\
    6a301a13010d40ed23489b890015d7e1b44024e356cd78518b16005a4cceac17964448ac53435e28dc76c933d7\
    5e319c1fda37dc8c8bf7f17106def3b9048648cfa7449e65e089ae1fa3ab5c335ff012c2bd0c6e98885c18458f\
    6ad95e8a142f951cd01806ddf63e695c7041e69dd2da6d48fc2e3a67ee40d039878aaea7abfa49b414968a285a\
    57144a5210cbca971107497ada777973c3d3173f16f9412e3d829d25b17ab71542c1d82fcc534b72aabb11be3"
);

impl CsidhParams<LIMBS_1792, 201, PrimeCsidh1792> {
    /// A proposition for CSIDH-1792.
    pub const CSIDH_1792: CsidhParams<LIMBS_1792, 201, PrimeCsidh1792> = CsidhParams {
        lis: [
            37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127,
            131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223,
            227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313,
            317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421,
            431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523,
            541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641,
            643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751,
            757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863,
            877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991,
            997, 1009, 1013, 1019, 1021, 1031, 1033, 1039, 1049, 1051, 1061, 1063, 1069, 1087,
            1091, 1093, 1097, 1103, 1109, 1117, 1123, 1129, 1151, 1153, 1163, 1171, 1181, 1187,
            1193, 1201, 1213, 1217, 1223, 1229, 1231, 1237, 1249, 1259, 1277, 1279, 1283, 1289,
            1291, 1301, 1657,
        ],
        p_minus_1_over_2: Uint::from_be_hex(
            "641a5cad421f4c8af8c7d30ddd7644cd32775534d2fe5012835f2c45c11f94430168dfac16\
            5f046e5dccb3aaa35180d098086a07691a44dc4800aebf0da201271ab66bc28c58b002d2667\
            560bcb22245629a1af146e3b6499ebaf18ce0fed1bee4645fbf8b8836f79dc82432467d3a24\
            f32f044d70fd1d5ae19aff809615e86374c442e0c22c7b56caf450a17ca8e680c036efb1f34\
            ae3820f34ee96d36a47e171d33f720681cc3c55753d5fd24da0a4b45142d2b8a25290865e54\
            b8883a4bd6d3bbcb9e1e98b9f8b7ca0971ec14e92d8bd5b8aa160ec17e629a5b9555d88df1",
        ),
        inverse_of_4: ConstMontyForm::new(&Uint::from_be_hex(
            "320d2e56a10fa6457c63e986eebb2266993baa9a697f280941af9622e08fca2180b46fd60b\
            2f82372ee659d551a8c0684c043503b48d226e2400575f86d100938d5b35e1462c580169333\
            ab05e591122b14d0d78a371db24cf5d78c6707f68df72322fdfc5c41b7bcee41219233e9d12\
            79978226b87e8ead70cd7fc04b0af431ba62217061163dab657a2850be547340601b77d8f9a\
            571c1079a774b69b523f0b8e99fb90340e61e2aba9eafe926d0525a28a1695c512948432f2a\
            5c441d25eb69dde5cf0f4c5cfc5be504b8f60a7496c5eadc550b0760bf314d2dcaaaec46f9",
        )),
        sqrt_of_p_times_4: Uint::from_be_hex(
            "00000000000000000000000000000000000000000000000000000000000000000000000000\
            000000000000000000000000000000000000000000000000000000000000000000000000000\
            000000000000000000000000000000000000000000000000000000000000000000000000003\
            8990052e73e9fb137778a2c8553d92bbe1abf6a3dbc42958ab43df8593c5c3a283e612ce65a\
            b290281ee56969fe3a0cd77a34926f2b21475b400ad2da4aa23668cf988de4f99ff9aa0ab4b\
            ca581ea99cfdf4a7cf03d270dbc49ccbb20d94d84eae8c9ed15e611d72f0bd5782773c19f7",
        ),
    };
}

impl<const LIMBS: usize, const N: usize, MOD: ConstMontyParams<LIMBS>> CsidhParams<LIMBS, N, MOD> {
    /// Constructs custom parameters.
    ///
    /// <div class="warning">
    /// The caller is responsible for the validity of the
    /// parameters. Valid parameters respect the following rules:
    ///
    /// - `lis` must be an array of mutually different prime numbers and contain the number 3.
    /// Their product, multiplied by 4, minus 1, must be a prime number that is called p.
    /// - `p_minus_1_over_2` must be equal to (p-1)/2.
    /// - `inverse_of_4` must be the inverse of 4 in the field of cardinality p.
    /// - `sqrt_of_p_times_4` must be (sqrt(p) * 4) rounded up.
    /// - The LIMBS generic given to `p_minus_1_over_2`, `inverse_of_4` and `sqrt_of_p_times_4` must
    /// be big enough to store numbers up to p. It is advised to use the smallest LIMBS number that
    /// satisfies this condition to minimize execution time. This translates to the following:
    ///     - LIMBS = min([0, `usize::MAX`]) such that
    ///     2<sup>(LIMBS * `target_pointer_width`)</sup> > p
    ///
    /// It is **unsound** to use invalid parameters. No validation is performed by the callee.
    /// **Use with care.**
    /// </div>
    ///
    /// # Example
    ///
    /// To construct the parameters from the prime numbers [3, 5, 7]:
    ///
    /// ```
    /// use csidh::{
    ///     impl_modulus, ConstMontyForm, CsidhParams, PrivateKey, PublicKey, SharedSecret, Uint
    /// };
    ///
    /// # fn main() {
    /// const LIMBS_3_5_7: usize = 1;
    /// impl_modulus!(Prime419, Uint<LIMBS_3_5_7>, "00000000000001a3");
    ///
    /// let lis = [3, 5, 7];
    /// let p_minus_1_over_2 = Uint::from(209u32);
    /// let inverse_of_4: ConstMontyForm<Prime419, LIMBS_3_5_7> =
    ///     ConstMontyForm::new(&Uint::from(105u32));
    /// let sqrt_of_p_times_4 = Uint::from(82u32);
    ///
    /// let params = CsidhParams::new(lis, p_minus_1_over_2, inverse_of_4, sqrt_of_p_times_4);
    /// # }
    /// ```
    #[must_use]
    pub const fn new(
        lis: [u64; N],
        p_minus_1_over_2: Uint<LIMBS>,
        inverse_of_4: ConstMontyForm<MOD, LIMBS>,
        sqrt_of_p_times_4: Uint<LIMBS>,
    ) -> Self {
        Self {
            lis,
            p_minus_1_over_2,
            inverse_of_4,
            sqrt_of_p_times_4,
        }
    }

    pub(crate) const fn lis(self) -> [u64; N] {
        self.lis
    }

    pub(crate) const fn p_minus_1_over_2(self) -> Uint<LIMBS> {
        self.p_minus_1_over_2
    }

    pub(crate) const fn inverse_of_4(self) -> ConstMontyForm<MOD, LIMBS> {
        self.inverse_of_4
    }

    pub(crate) const fn sqrt_of_p_times_4(self) -> Uint<LIMBS> {
        self.sqrt_of_p_times_4
    }
}
