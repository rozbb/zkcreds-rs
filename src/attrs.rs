use ark_crypto_primitives::commitment::{constraints::CommitmentGadget, CommitmentScheme};
use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget};

/// This describes any object which holds attributes. The requirement is that it holds a commitment
/// nonce and defines a way to commit to itself.
pub trait Attrs<AC: CommitmentScheme>: Default {
    fn commit(&self) -> AC::Output;
}

/// This describes the ZK-circuit version of `Attrs`. The only requirement is that it holds a
/// commitment nonce, defines a way to commit to itself, and can be constructed from its
/// corresponding `Attrs` object.
pub trait AttrsVar<ConstraintF, A, AC, ACG>:
    AllocVar<A, ConstraintF> + EqGadget<ConstraintF>
where
    ConstraintF: PrimeField,
    A: Attrs<AC>,
    AC: CommitmentScheme,
    ACG: CommitmentGadget<AC, ConstraintF>,
{
    fn commit(&self) -> ACG::OutputVar;
}
