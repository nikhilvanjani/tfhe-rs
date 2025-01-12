#![allow(unused_imports)]

use tfhe::core_crypto::algorithms::slice_algorithms::*;
use tfhe::core_crypto::algorithms::*;
use tfhe::core_crypto::commons::ciphertext_modulus::CiphertextModulusKind;
use tfhe::core_crypto::commons::generators::{EncryptionRandomGenerator, SecretRandomGenerator};
#[cfg(feature = "zk-pok")]
use tfhe::core_crypto::commons::math::random::BoundedDistribution;
use tfhe::core_crypto::commons::math::random::{
    DefaultRandomGenerator, Distribution, RandomGenerable, RandomGenerator, Uniform, UniformBinary,
};
use tfhe::core_crypto::commons::parameters::*;
use tfhe::core_crypto::commons::traits::*;
use tfhe::core_crypto::entities::*;
use rayon::prelude::*;
use pulp::Scalar;

use crate::deterministic_encryption::*;


pub fn lwe_ciphertext_add_pk_random_vectors<Scalar>(
    output: &mut PublicKeyRandomVectors<Scalar>,
    lhs: &PublicKeyRandomVectors<Scalar>,
    rhs: &PublicKeyRandomVectors<Scalar>,
) where
    Scalar: UnsignedInteger,
{
    assert_eq!(
        lhs.binary_random_vector.len(),
        rhs.binary_random_vector.len(),
        "Mismatched vector length between lhs ({:?}) and rhs ({:?}) masks",
        lhs.binary_random_vector.len(),
        rhs.binary_random_vector.len()
    );

    assert_eq!(
        output.binary_random_vector.len(),
        rhs.binary_random_vector.len(),
        "Mismatched vector length between output ({:?}) and rhs ({:?}) masks",
        output.binary_random_vector.len(),
        rhs.binary_random_vector.len()
    );

    slice_wrapping_add(&mut output.binary_random_vector, &lhs.binary_random_vector, &rhs.binary_random_vector);
}

pub fn lwe_ciphertext_add_mask<Scalar>(
    output: &mut LweMask<&mut [Scalar]>,
    lhs: &LweMask<&[Scalar]>,
    rhs: &LweMask<&[Scalar]>,
) where
    Scalar: UnsignedInteger,
{
    assert_eq!(
        lhs.lwe_dimension(),
        rhs.lwe_dimension(),
        "Mismatched LWE dimension between lhs ({:?}) and rhs ({:?}) masks",
        lhs.lwe_dimension(),
        rhs.lwe_dimension()
    );

    assert_eq!(
        output.lwe_dimension(),
        rhs.lwe_dimension(),
        "Mismatched LWE dimension between output ({:?}) and rhs ({:?}) masks",
        output.lwe_dimension(),
        rhs.lwe_dimension()
    );

    slice_wrapping_add(&mut output.as_mut(), &lhs.as_ref(), &rhs.as_ref());
}

pub fn lwe_ciphertext_add_noise<Scalar>(
    // output: &mut Scalar,
    lhs: &Scalar,
    rhs: &Scalar,
) -> Scalar
where
    Scalar: UnsignedInteger,
{

    // *output = 0;
    // output.wrapping_add(*lhs).wrapping_add(*rhs);
    // output = output.wrapping_add(*lhs).wrapping_add(*rhs);
    let output = lhs.wrapping_add(*rhs);
    output
    // slice_wrapping_add(&mut output.binary_random_vector, &lhs.binary_random_vector, &rhs.binary_random_vector);
}

pub fn lwe_ciphertext_cleartext_mul_pk_random_vectors<Scalar>(
    output: &mut PublicKeyRandomVectors<Scalar>,
    lhs: &PublicKeyRandomVectors<Scalar>,
    rhs: Cleartext<Scalar>,
) where
    Scalar: UnsignedInteger,
{
    assert_eq!(
        output.binary_random_vector.len(),
        lhs.binary_random_vector.len(),
        "Mismatched vector length between output ({:?}) and lhs ({:?}) masks",
        output.binary_random_vector.len(),
        lhs.binary_random_vector.len()
    );
    output.binary_random_vector = lhs.binary_random_vector.clone();
    slice_wrapping_scalar_mul_assign(&mut output.binary_random_vector, rhs.0);
    // output.as_mut().copy_from_slice(lhs.as_ref());
    // lwe_ciphertext_cleartext_mul_assign(output, rhs);
}

pub fn lwe_ciphertext_cleartext_mul_mask<Scalar>(
    output: &mut LweMask<&mut [Scalar]>,
    lhs: &LweMask<&[Scalar]>,
    rhs: &Scalar,
) where
    Scalar: UnsignedInteger,
{
    assert_eq!(
        output.lwe_dimension(),
        lhs.lwe_dimension(),
        "Mismatched LWE dimension between output ({:?}) and lhs ({:?}) masks",
        output.lwe_dimension(),
        lhs.lwe_dimension()
    );

    // output = output + lhs * rhs
    slice_wrapping_add_scalar_mul_assign(output.as_mut(), lhs.as_ref(), *rhs);
}

pub fn lwe_ciphertext_cleartext_mul_noise<Scalar>(
    // output: &mut Scalar,
    lhs: &Scalar,
    rhs: &Scalar,
) -> Scalar
where
    Scalar: UnsignedInteger,
{

    // *output = 0;
    // output.wrapping_add(*lhs).wrapping_add(*rhs);
    // output = output.wrapping_add(*lhs).wrapping_add(*rhs);
    let output = lhs.wrapping_mul(*rhs);
    output
    // slice_wrapping_add(&mut output.binary_random_vector, &lhs.binary_random_vector, &rhs.binary_random_vector);
}