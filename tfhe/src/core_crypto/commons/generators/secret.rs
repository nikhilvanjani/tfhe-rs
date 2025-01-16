//! Module containing primitives pertaining to random generation in the context of secret key
//! generation.

use crate::core_crypto::commons::math::random::{
    ByteRandomGenerator, RandomGenerable, RandomGenerator, Seed, UniformBinary, ParallelByteRandomGenerator
};
use crate::core_crypto::prelude::LwePublicKeyZeroEncryptionCount;
use rayon::prelude::*;
use tfhe_csprng::generators::ForkError;

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

    pub(crate) fn try_fork(
        &mut self,
        n_child: usize,
        // mask_bytes: EncryptionMaskByteCount,
        zero_encryption_per_child_count: LwePublicKeyZeroEncryptionCount,
    ) -> Result<impl Iterator<Item = Self>, ForkError> {
        // We try to fork the generators
        // let mask_iter = self.gen.try_fork(n_child, mask_bytes.0)?;
        let secret_iter = self.0.try_fork(n_child, zero_encryption_per_child_count.0)?;

        // We return a proper iterator.
        // Ok(mask_iter.map(|gen| Self { gen }))
        Ok(secret_iter.map(|gen| Self(gen)))
    }

    pub fn try_fork_from_config(
        &mut self,
        fork_config: SecretRandomGeneratorForkConfig,
    ) -> Result<impl Iterator<Item = Self>, ForkError> {
        self.try_fork(
            fork_config.children_count,
            fork_config.zero_encryption_per_child_count,
        )
    }

}

impl<G: ParallelByteRandomGenerator> SecretRandomGenerator<G> {
    // Forks generator into a parallel iterator.
    pub(crate) fn par_try_fork(
        &mut self,
        n_child: usize,
        // mask_bytes: EncryptionMaskByteCount,
        zero_encryption_per_child_count: LwePublicKeyZeroEncryptionCount,
    ) -> Result<impl IndexedParallelIterator<Item = Self>, ForkError> {
        // We try to fork the generators
        // let mask_iter = self.gen.par_try_fork(n_child, mask_bytes.0)?;
        let secret_iter = self.0.par_try_fork(n_child, zero_encryption_per_child_count.0)?;

        // We return a proper iterator.
        // Ok(mask_iter.map(|gen| Self { gen }))
        Ok(secret_iter.map(|gen| Self(gen)))
    }

    pub fn par_try_fork_from_config(
        &mut self,
        fork_config: SecretRandomGeneratorForkConfig,
    ) -> Result<impl IndexedParallelIterator<Item = Self>, ForkError> {
        self.par_try_fork(
            fork_config.children_count,
            fork_config.zero_encryption_per_child_count,
        )
    }

}

#[derive(Clone, Copy, Debug)]
pub struct SecretRandomGeneratorForkConfig {
    children_count: usize,
    zero_encryption_per_child_count: LwePublicKeyZeroEncryptionCount,
}

impl SecretRandomGeneratorForkConfig {
    // pub fn new<Scalar, MaskDistribution, NoiseDistribution>(
    pub fn new(
        children_count: usize,
        // mask_element_per_child_count: EncryptionMaskSampleCount,
        // mask_distribution: MaskDistribution,
        // noise_element_per_child_count: EncryptionNoiseSampleCount,
        // noise_distribution: NoiseDistribution,
        // modulus: Option<Scalar>,
        zero_encryption_per_child_count: LwePublicKeyZeroEncryptionCount,
    ) -> Self
    // where
        // MaskDistribution: Distribution,
        // NoiseDistribution: Distribution,
        // Scalar: Copy
            // + RandomGenerable<MaskDistribution, CustomModulus = Scalar>
            // + RandomGenerable<NoiseDistribution, CustomModulus = Scalar>,
    {

        // zero_encryption_per_child_byte_count = zero_encryption_per_child_count * 1
        // since a single bit is used to decide whether to choose a zero_encryption or not during public key lwe encryption
        Self {
            children_count,
            zero_encryption_per_child_count: zero_encryption_per_child_count,
        }
    }

    pub fn children_count(&self) -> usize {
        self.children_count
    }
    pub fn zero_encryption_per_child_count(&self) -> LwePublicKeyZeroEncryptionCount {
        self.zero_encryption_per_child_count
    }

}
