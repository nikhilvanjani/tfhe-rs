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

// /// This struct stores random vectors that were generated during
// /// the encryption of a lwe ciphertext or lwe compact ciphertext list.
// ///
// /// These are needed by the zero-knowledge proof
// pub struct SecretKeyRandomVectors<Scalar: Encryptable<Uniform, Distribution>, OutputCont: ContainerMut<Element = Scalar>> {
//     // This is the random mask
//     // mask: &mut LweMask<OutputCont>,
//     mask: LweMask<OutputCont>,
//     // mask: LweMask<&mut [Scalar]>,
//     // This is the noise
//     noise: Vec<Scalar>,
// }



// /// Convenience function to share the core logic of the LWE encryption between all functions needing
// /// it.
// pub fn fill_lwe_mask_and_body_for_encryption_ret_mask_and_noise<Scalar, NoiseDistribution, KeyCont, OutputCont, Gen>(
//     lwe_secret_key: &LweSecretKey<KeyCont>,
//     output_mask: &mut LweMask<&mut [Scalar]>, // Changed to match type from get_mut_mask_and_body
//     // output_mask: &mut LweMask<OutputCont>,
//     output_body: &mut LweBodyRefMut<Scalar>,
//     encoded: Plaintext<Scalar>,
//     noise_distribution: NoiseDistribution,
//     generator: &mut EncryptionRandomGenerator<Gen>,
// ) -> SecretKeyRandomVectors<Scalar, OutputCont>
// where
//     Scalar: Encryptable<Uniform, NoiseDistribution>,
//     NoiseDistribution: Distribution,
//     KeyCont: Container<Element = Scalar>,
//     OutputCont: ContainerMut<Element = Scalar>,
//     Gen: ByteRandomGenerator,
// {
//     assert_eq!(
//         output_mask.ciphertext_modulus(),
//         output_body.ciphertext_modulus(),
//         "Mismatched moduli between mask ({:?}) and body ({:?})",
//         output_mask.ciphertext_modulus(),
//         output_body.ciphertext_modulus()
//     );

//     let ciphertext_modulus = output_mask.ciphertext_modulus();

//     if !ciphertext_modulus.is_compatible_with_native_modulus() {
//         println!("NOT IMPLEMENTED: ciphertext_modulus NOT compatible with native modulus case");
//     }
//     fill_lwe_mask_and_body_for_encryption_native_mod_compatible_ret_mask_and_noise(
//         lwe_secret_key,
//         output_mask,
//         output_body,
//         encoded,
//         noise_distribution,
//         generator,
//     )

// }

// pub fn fill_lwe_mask_and_body_for_encryption_native_mod_compatible_ret_mask_and_noise<
//     Scalar,
//     NoiseDistribution,
//     KeyCont,
//     OutputCont,
//     Gen,
// >(
//     lwe_secret_key: &LweSecretKey<KeyCont>,
//     output_mask: &mut LweMask<&mut [Scalar]>, // Changed to match type from get_mut_mask_and_body
//     // output_mask: &mut LweMask<OutputCont>,
//     output_body: &mut LweBodyRefMut<Scalar>,
//     encoded: Plaintext<Scalar>,
//     noise_distribution: NoiseDistribution,
//     generator: &mut EncryptionRandomGenerator<Gen>,
// ) -> SecretKeyRandomVectors<Scalar, OutputCont>
// where
//     Scalar: Encryptable<Uniform, NoiseDistribution>,
//     NoiseDistribution: Distribution,
//     KeyCont: Container<Element = Scalar>,
//     OutputCont: ContainerMut<Element = Scalar>,
//     Gen: ByteRandomGenerator,
// {
//     assert_eq!(
//         output_mask.ciphertext_modulus(),
//         output_body.ciphertext_modulus(),
//         "Mismatched moduli between mask ({:?}) and body ({:?})",
//         output_mask.ciphertext_modulus(),
//         output_body.ciphertext_modulus()
//     );

//     let ciphertext_modulus = output_mask.ciphertext_modulus();

//     assert!(ciphertext_modulus.is_compatible_with_native_modulus());

//     // generate a randomly uniform mask
//     generator
//         .fill_slice_with_random_uniform_mask_custom_mod(output_mask.as_mut(), ciphertext_modulus);

//     // generate an error from the given noise_distribution
//     let noise =
//         generator.random_noise_from_distribution_custom_mod(noise_distribution, ciphertext_modulus);
//     // compute the multisum between the secret key and the mask
//     let mask_key_dot_product =
//         slice_wrapping_dot_product(output_mask.as_ref(), lwe_secret_key.as_ref());

//     // Store sum(ai * si) + delta * m + e in the body
//     *output_body.data = mask_key_dot_product
//         .wrapping_add(encoded.0)
//         .wrapping_add(noise);

//     match ciphertext_modulus.kind() {
//         CiphertextModulusKind::Native => (),
//         CiphertextModulusKind::NonNativePowerOfTwo => {
//             // Manage power of 2 encoding to map to the native case
//             let torus_scaling = ciphertext_modulus.get_power_of_two_scaling_to_native_torus();
//             slice_wrapping_scalar_mul_assign(output_mask.as_mut(), torus_scaling);
//             *output_body.data = (*output_body.data).wrapping_mul(torus_scaling);
//         }
//         CiphertextModulusKind::Other => unreachable!(),
//     };
//     println!("Reached return point");
//     SecretKeyRandomVectors {
//         mask: *output_mask,
//         noise: vec![noise]
//     }

// }

// pub fn encrypt_lwe_ciphertext_ret_mask_and_noise<Scalar, NoiseDistribution, KeyCont, OutputCont, Gen>(
//     lwe_secret_key: &LweSecretKey<KeyCont>,
//     output: &mut LweCiphertext<OutputCont>,
//     encoded: Plaintext<Scalar>,
//     noise_distribution: NoiseDistribution,
//     generator: &mut EncryptionRandomGenerator<Gen>,
// ) -> SecretKeyRandomVectors<Scalar, OutputCont>
// where
//     Scalar: Encryptable<Uniform, NoiseDistribution>,
//     NoiseDistribution: Distribution,
//     KeyCont: Container<Element = Scalar>,
//     OutputCont: ContainerMut<Element = Scalar>,
//     Gen: ByteRandomGenerator,
// {
//     assert!(
//         output.lwe_size().to_lwe_dimension() == lwe_secret_key.lwe_dimension(),
//         "Mismatch between LweDimension of output ciphertext and input secret key. \
//         Got {:?} in output, and {:?} in secret key.",
//         output.lwe_size().to_lwe_dimension(),
//         lwe_secret_key.lwe_dimension()
//     );

//     let (mut mask, mut body) = output.get_mut_mask_and_body();

//     fill_lwe_mask_and_body_for_encryption_ret_mask_and_noise(
//         lwe_secret_key,
//         &mut mask,
//         &mut body,
//         encoded,
//         noise_distribution,
//         generator,
//     )
// }


/////////////////////
// public key setting below
/////////////////////

/// This struct stores random vectors that were generated during
/// the encryption of a lwe ciphertext or lwe compact ciphertext list.
///
/// These are needed by the zero-knowledge proof
pub struct PublicKeyRandomVectors<Scalar> {
// pub struct PublicKeyRandomVectors<Scalar: Encryptable<Uniform, dyn Distribution>> {
    pub binary_random_vector: Vec<Scalar>,
}

impl<Scalar: Clone> Clone for PublicKeyRandomVectors<Scalar> {
    fn clone(&self) -> Self {
        PublicKeyRandomVectors {
            binary_random_vector: self.binary_random_vector.clone(),
        }
    }
}

pub fn encrypt_lwe_ciphertext_with_public_key_ret_mask<Scalar, KeyCont, OutputCont, Gen>(
    lwe_public_key: &LwePublicKey<KeyCont>,
    output: &mut LweCiphertext<OutputCont>,
    encoded: Plaintext<Scalar>,
    generator: &mut SecretRandomGenerator<Gen>,
) -> PublicKeyRandomVectors<Scalar>
where
    Scalar: UnsignedTorus,
    KeyCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert_eq!(
        lwe_public_key.ciphertext_modulus(),
        output.ciphertext_modulus(),
        "Mismatched moduli between lwe_public_key ({:?}) and output ({:?})",
        lwe_public_key.ciphertext_modulus(),
        output.ciphertext_modulus()
    );

    assert!(
        output.lwe_size().to_lwe_dimension() == lwe_public_key.lwe_size().to_lwe_dimension(),
        "Mismatch between LweDimension of output ciphertext and input public key. \
        Got {:?} in output, and {:?} in public key.",
        output.lwe_size().to_lwe_dimension(),
        lwe_public_key.lwe_size().to_lwe_dimension()
    );

    output.as_mut().fill(Scalar::ZERO);

    let mut tmp_zero_encryption =
        LweCiphertext::new(Scalar::ZERO, output.lwe_size(), output.ciphertext_modulus());

    let mut ct_choice = vec![Scalar::ZERO; lwe_public_key.zero_encryption_count().0];

    generator.fill_slice_with_random_uniform_binary(&mut ct_choice);

    // Add the public encryption of zeros to get the zero encryption
    for (&chosen, public_encryption_of_zero) in ct_choice.iter().zip(lwe_public_key.iter()) {
        // chosen is 1 if chosen, 0 otherwise, so use a multiplication to avoid having a branch
        // depending on a value that's supposed to remain secret
        lwe_ciphertext_cleartext_mul(
            &mut tmp_zero_encryption,
            &public_encryption_of_zero,
            Cleartext(chosen),
        );
        lwe_ciphertext_add_assign(output, &tmp_zero_encryption);
    }

    lwe_ciphertext_plaintext_add_assign(output, encoded);

    PublicKeyRandomVectors{
        binary_random_vector: ct_choice
    }
}

pub fn encrypt_lwe_ciphertext_with_public_key_and_mask<Scalar, KeyCont, OutputCont>(
    lwe_public_key: &LwePublicKey<KeyCont>,
    output: &mut LweCiphertext<OutputCont>,
    encoded: Plaintext<Scalar>,
    mask: Vec<Scalar>,
)
where
    Scalar: UnsignedTorus,
    KeyCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
{
    assert_eq!(
        lwe_public_key.ciphertext_modulus(),
        output.ciphertext_modulus(),
        "Mismatched moduli between lwe_public_key ({:?}) and output ({:?})",
        lwe_public_key.ciphertext_modulus(),
        output.ciphertext_modulus()
    );

    assert!(
        output.lwe_size().to_lwe_dimension() == lwe_public_key.lwe_size().to_lwe_dimension(),
        "Mismatch between LweDimension of output ciphertext and input public key. \
        Got {:?} in output, and {:?} in public key.",
        output.lwe_size().to_lwe_dimension(),
        lwe_public_key.lwe_size().to_lwe_dimension()
    );

    assert!(
        mask.len() == lwe_public_key.zero_encryption_count().0,
        "Mismatch between length of mask and input public key's zero_encryption_count. \
        Got {:?} in mask, and {:?} in public key.",
        mask.len(),
        lwe_public_key.zero_encryption_count().0
    );

    output.as_mut().fill(Scalar::ZERO);

    let mut tmp_zero_encryption =
        LweCiphertext::new(Scalar::ZERO, output.lwe_size(), output.ciphertext_modulus());

    // let mut ct_choice = vec![Scalar::ZERO; lwe_public_key.zero_encryption_count().0];
    // generator.fill_slice_with_random_uniform_binary(&mut ct_choice);

    // Add the public encryption of zeros to get the zero encryption
    for (&chosen, public_encryption_of_zero) in mask.iter().zip(lwe_public_key.iter()) {
        // chosen is 1 if chosen, 0 otherwise, so use a multiplication to avoid having a branch
        // depending on a value that's supposed to remain secret
        lwe_ciphertext_cleartext_mul(
            &mut tmp_zero_encryption,
            &public_encryption_of_zero,
            Cleartext(chosen),
        );
        lwe_ciphertext_add_assign(output, &tmp_zero_encryption);
    }

    lwe_ciphertext_plaintext_add_assign(output, encoded);
}

pub fn lwe_ciphertext_add_mask<Scalar>(
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

pub fn lwe_ciphertext_cleartext_mul_mask<Scalar>(
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
