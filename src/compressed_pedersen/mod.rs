use ark_ec::{
    twisted_edwards_extended::GroupProjective as TEProjective, ProjectiveCurve, TEModelParameters,
};
use ark_ff::{bytes::ToBytes, BitIteratorLE, Field, FpParameters, PrimeField, ToConstraintField};
use ark_std::io::{Result as IoResult, Write};
use ark_std::marker::PhantomData;
use ark_std::rand::Rng;
use ark_std::UniformRand;
use derivative::Derivative;

use ark_crypto_primitives::{
    commitment::CommitmentScheme,
    crh::{
        pedersen::{self, Window},
        CRH as CRHTrait,
    },
};

pub type Error = Box<dyn ark_std::error::Error>;

pub mod constraints;

#[derive(Derivative)]
#[derivative(Clone(bound = "P: TEModelParameters"))]
pub struct Parameters<P: TEModelParameters> {
    pub randomness_generator: Vec<TEProjective<P>>,
    pub generators: Vec<Vec<TEProjective<P>>>,
}

pub struct Commitment<P: TEModelParameters, W: Window> {
    group: PhantomData<P>,
    window: PhantomData<W>,
}

#[derive(Derivative)]
#[derivative(Clone, PartialEq, Debug, Eq, Default)]
pub struct Randomness<P: TEModelParameters>(pub P::ScalarField);

impl<P: TEModelParameters> UniformRand for Randomness<P> {
    #[inline]
    fn rand<R: Rng + ?Sized>(rng: &mut R) -> Self {
        Randomness(UniformRand::rand(rng))
    }
}

impl<P: TEModelParameters> ToBytes for Randomness<P> {
    fn write<W: Write>(&self, writer: W) -> IoResult<()> {
        self.0.write(writer)
    }
}

impl<P: TEModelParameters, W: Window> CommitmentScheme for Commitment<P, W> {
    type Parameters = Parameters<P>;
    type Randomness = Randomness<P>;
    type Output = P::BaseField;

    fn setup<R: Rng>(rng: &mut R) -> Result<Self::Parameters, Error> {
        let num_powers = <P::ScalarField as PrimeField>::Params::MODULUS_BITS as usize;
        let randomness_generator =
            pedersen::CRH::<TEProjective<P>, W>::generator_powers(num_powers, rng);
        let generators = pedersen::CRH::<TEProjective<P>, W>::create_generators(rng);

        Ok(Self::Parameters {
            randomness_generator,
            generators,
        })
    }

    fn commit(
        parameters: &Self::Parameters,
        input: &[u8],
        randomness: &Self::Randomness,
    ) -> Result<Self::Output, Error> {
        // If the input is too long, return an error.
        if input.len() > W::WINDOW_SIZE * W::NUM_WINDOWS {
            panic!("incorrect input length: {:?}", input.len());
        }
        // Pad the input to the necessary length.
        let mut padded_input = Vec::with_capacity(input.len());
        let mut input = input;
        if (input.len() * 8) < W::WINDOW_SIZE * W::NUM_WINDOWS {
            padded_input.extend_from_slice(input);
            let padded_length = (W::WINDOW_SIZE * W::NUM_WINDOWS) / 8;
            padded_input.resize(padded_length, 0u8);
            input = padded_input.as_slice();
        }
        assert_eq!(parameters.generators.len(), W::NUM_WINDOWS);
        let input = input.to_vec();
        // Invoke Pedersen CRH here, to prevent code duplication.

        let crh_parameters = pedersen::Parameters {
            generators: parameters.generators.clone(),
        };
        let mut result: TEProjective<P> =
            <pedersen::CRH<TEProjective<P>, W> as CRHTrait>::evaluate(
                &crh_parameters,
                input.as_slice(),
            )?
            .into();

        // Compute h^r.
        for (bit, power) in BitIteratorLE::new(randomness.0.into_repr())
            .into_iter()
            .zip(&parameters.randomness_generator)
        {
            if bit {
                result += power
            }
        }

        Ok(result.into_affine().x)
    }
}

impl<ConstraintF: Field, P: TEModelParameters + ToConstraintField<ConstraintF>>
    ToConstraintField<ConstraintF> for Parameters<P>
{
    #[inline]
    fn to_field_elements(&self) -> Option<Vec<ConstraintF>> {
        Some(Vec::new())
    }
}
