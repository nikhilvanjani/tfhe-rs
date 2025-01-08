//! Module containing primitives pertaining to random generation in the context of secret key
//! generation.

use crate::core_crypto::commons::math::random::{
    ByteRandomGenerator, RandomGenerable, RandomGenerator, Seed, UniformBinary,
};

/// A random number generator which can be used to generate secret keys.
pub struct SecretRandomGenerator<G: ByteRandomGenerator>(RandomGenerator<G>);

impl<G: ByteRandomGenerator> SecretRandomGenerator<G> {
    /// Create a new generator, optionally seeding it with the given value.
    pub fn new(seed: Seed) -> Self {
        Self(RandomGenerator::new(seed))
    }

    /// Return the number of remaining bytes, if the generator is bounded.
    pub fn remaining_bytes(&self) -> Option<usize> {
        self.0.remaining_bytes()
    }

    // Nikhil: changed visibility from pub(crate) to pub to make it accessible by tfhe/examples/randomness_tracking/lwe_encryption.rs
    pub fn fill_slice_with_random_uniform_binary<Scalar>(&mut self, slice: &mut [Scalar])
    // pub(crate) fn fill_slice_with_random_uniform_binary<Scalar>(&mut self, slice: &mut [Scalar])
    where
        Scalar: RandomGenerable<UniformBinary>,
    {
        self.0.fill_slice_with_random_uniform_binary(slice);
    }

    pub(crate) fn generate_random_uniform_binary<Scalar>(&mut self) -> Scalar
    where
        Scalar: RandomGenerable<UniformBinary>,
    {
        self.0.random_uniform_binary()
    }
}
