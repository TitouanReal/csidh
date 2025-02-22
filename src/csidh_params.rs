/// Parameters for 1024 bits CSIDH
pub mod csidh_1024;
/// Parameters for 1792 bits CSIDH
pub mod csidh_1792;
/// Parameters for 512 bits CSIDH
pub mod csidh_512;

use crypto_bigint::{
    Uint,
    modular::{ConstMontyForm, ConstMontyParams},
};

/// Parameters of the CSIDH key exchange.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CsidhParams<const LIMBS: usize, const N: usize, MOD: ConstMontyParams<LIMBS>> {
    lis: [u64; N],
    p_minus_1_over_2: Uint<LIMBS>,
    inverse_of_4: ConstMontyForm<MOD, LIMBS>,
    sqrt_of_p_times_4: Uint<LIMBS>,
}

impl<const LIMBS: usize, const N: usize, MOD: ConstMontyParams<LIMBS>> CsidhParams<LIMBS, N, MOD> {
    /// Constructs custom parameters.
    ///
    /// <div class="warning">
    /// The caller is responsible for the validity of the
    /// parameters. Valid parameters respect the following rules:
    ///
    /// - `lis` must be an array of mutually different prime numbers and contain the number 3.
    ///   Their product, multiplied by 4, minus 1, must be a prime number that is called p.
    /// - `p_minus_1_over_2` must be equal to (p-1)/2.
    /// - `inverse_of_4` must be the inverse of 4 in the field of cardinality p.
    /// - `sqrt_of_p_times_4` must be (sqrt(p) * 4) rounded up.
    /// - The LIMBS generic given to `p_minus_1_over_2`, `inverse_of_4` and `sqrt_of_p_times_4` must
    ///   be big enough to store numbers up to p. It is advised to use the smallest LIMBS number
    ///   that satisfies this condition to minimize execution time. This translates to the
    ///   following:
    ///     - LIMBS = min([0, `usize::MAX`]) such that
    ///       2<sup>(LIMBS * `target_pointer_width`)</sup> > p
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
