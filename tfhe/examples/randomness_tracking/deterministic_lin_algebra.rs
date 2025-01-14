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
    lhs: &LweBody<Scalar>,
    rhs: &LweBody<Scalar>,
) -> LweBody<Scalar>
where
    Scalar: UnsignedInteger,
{
    assert_eq!(
        lhs.ciphertext_modulus(),
        rhs.ciphertext_modulus(),
        "Mismatched ciphertext modulus between lhs ({:?}) and rhs ({:?}) LWE noises",
        lhs.ciphertext_modulus(),
        rhs.ciphertext_modulus()
    );

    let mut output = Scalar::ZERO;
    output = output.wrapping_add(lhs.data).wrapping_add(rhs.data);
    LweBody::new(output, lhs.ciphertext_modulus())
}

pub fn glwe_ciphertext_add_mask<Scalar>(
    output: &mut GlweMask<&mut [Scalar]>,
    lhs: &GlweMask<&[Scalar]>,
    rhs: &GlweMask<&[Scalar]>,
) where
    Scalar: UnsignedInteger,
{
    assert_eq!(
        lhs.glwe_dimension(),
        rhs.glwe_dimension(),
        "Mismatched GLWE dimension between lhs ({:?}) and rhs ({:?}) masks",
        lhs.glwe_dimension(),
        rhs.glwe_dimension()
    );

    assert_eq!(
        output.glwe_dimension(),
        rhs.glwe_dimension(),
        "Mismatched GLWE dimension between output ({:?}) and rhs ({:?}) masks",
        output.glwe_dimension(),
        rhs.glwe_dimension()
    );
    assert_eq!(
        lhs.ciphertext_modulus(),
        rhs.ciphertext_modulus(),
        "Mismatched moduli between lhs ({:?}) and rhs ({:?}) GLWE masks",
        lhs.ciphertext_modulus(),
        rhs.ciphertext_modulus()
    );

    assert_eq!(
        output.ciphertext_modulus(),
        rhs.ciphertext_modulus(),
        "Mismatched moduli between output ({:?}) and rhs ({:?}) GLWE masks",
        output.ciphertext_modulus(),
        rhs.ciphertext_modulus()
    );

    slice_wrapping_add(output.as_mut(), lhs.as_ref(), rhs.as_ref());
}

pub fn glwe_ciphertext_add_noise<Scalar>(
    lhs: &GlweBody<Vec<Scalar>>,
    rhs: &GlweBody<Vec<Scalar>>,
) -> GlweBody<Vec<Scalar>>
where
    Scalar: UnsignedInteger,
{
    assert_eq!(
        lhs.as_ref().container_len(),
        rhs.as_ref().container_len(),
        "Mismatched container length between lhs ({:?}) and rhs ({:?}) GlweBody noises",
        lhs.as_ref().container_len(),
        rhs.as_ref().container_len()
    );
    assert_eq!(
        lhs.ciphertext_modulus(),
        rhs.ciphertext_modulus(),
        "Mismatched ciphertext_modulus between lhs ({:?}) and rhs ({:?}) GlweBody noises",
        lhs.ciphertext_modulus(),
        rhs.ciphertext_modulus()
    );
    let mut output = vec![Scalar::ZERO; lhs.as_ref().container_len()];
    slice_wrapping_add(&mut output, lhs.as_ref(), rhs.as_ref());
    GlweBody::from_container(output, lhs.ciphertext_modulus())
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

    // output = output + lhs * rhs. ASSUMPTION: 'output' provided as input is 0.
    slice_wrapping_add_scalar_mul_assign(output.as_mut(), lhs.as_ref(), *rhs);
}

pub fn lwe_ciphertext_cleartext_mul_noise<Scalar>(
    lhs: &LweBody<Scalar>,
    rhs: &Scalar,
) -> LweBody<Scalar>
where
    Scalar: UnsignedInteger,
{

    let mut output = Scalar::ZERO;
    output = output.wrapping_add(lhs.data).wrapping_mul(*rhs);
    LweBody::new(output, lhs.ciphertext_modulus())
    // output
}

pub fn glwe_ciphertext_cleartext_mul_mask<Scalar>(
    output: &mut GlweMask<&mut [Scalar]>,
    lhs: &GlweMask<&[Scalar]>,
    rhs: &Scalar,
) where
    Scalar: UnsignedInteger,
{
    assert_eq!(
        output.glwe_dimension(),
        lhs.glwe_dimension(),
        "Mismatched GLWE dimension between output ({:?}) and lhs ({:?}) masks",
        output.glwe_dimension(),
        lhs.glwe_dimension()
    );
    assert_eq!(
        output.ciphertext_modulus(),
        lhs.ciphertext_modulus(),
        "Mismatched moduli between output ({:?}) and lhs ({:?}) GlweMask",
        output.ciphertext_modulus(),
        lhs.ciphertext_modulus()
    );

    // output = output + lhs * rhs. ASSUMPTION: 'output' provided as input is 0.
    slice_wrapping_add_scalar_mul_assign(output.as_mut(), lhs.as_ref(), *rhs);
}

pub fn glwe_ciphertext_cleartext_mul_noise<Scalar>(
    lhs: &GlweBody<Vec<Scalar>>,
    rhs: &Scalar,
) -> GlweBody<Vec<Scalar>>
where
    Scalar: UnsignedInteger,
{
    let mut output = vec![Scalar::ZERO; lhs.as_ref().container_len()];
    slice_wrapping_add_scalar_mul_assign(&mut output, lhs.as_ref(), *rhs);
    GlweBody::from_container(output, lhs.ciphertext_modulus())
}