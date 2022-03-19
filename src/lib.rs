//pub mod api;
pub mod attrs;
pub mod birth;
pub mod com_forest;
pub mod com_tree;
mod common;
mod identity_crh;
pub mod link;
mod merkle_forest;
//mod multishow;
mod compressed_pedersen;
pub mod pred;
pub mod proof_data_structures;
pub mod revealing_multishow;
mod sparse_merkle;
mod test_util;

pub type Error = Box<dyn ark_std::error::Error>;
pub use identity_crh::Bytestring;

use ark_crypto_primitives::commitment::{constraints::CommitmentGadget, CommitmentScheme};

pub type Com<C> = <C as CommitmentScheme>::Output;
pub type ComVar<C, CG, F> = <CG as CommitmentGadget<C, F>>::OutputVar;
pub type ComNonce<C> = <C as CommitmentScheme>::Randomness;
pub type ComNonceVar<C, CG, F> = <CG as CommitmentGadget<C, F>>::RandomnessVar;
pub type ComParam<C> = <C as CommitmentScheme>::Parameters;
pub type ComParamVar<C, CG, F> = <CG as CommitmentGadget<C, F>>::ParametersVar;
