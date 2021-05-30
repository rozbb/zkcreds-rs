use ark_crypto_primitives::crh::pedersen;

#[derive(Clone)]
pub struct Window4x256;
impl pedersen::Window for Window4x256 {
    const WINDOW_SIZE: usize = 128;
    const NUM_WINDOWS: usize = 8;
}
