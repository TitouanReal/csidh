#[cfg(target_pointer_width = "32")]
pub const LIMBS: usize = 16;
#[cfg(target_pointer_width = "64")]
pub const LIMBS: usize = 8;
