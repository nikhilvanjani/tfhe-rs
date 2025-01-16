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

use tfhe::core_crypto::commons::math::decomposition::{
    DecompositionLevel, DecompositionTerm, DecompositionTermNonNative, SignedDecomposer,
};
use tfhe::core_crypto::algorithms::*;
use tfhe::core_crypto::algorithms::polynomial_algorithms::*;
use tfhe_fft::c64;
use tfhe::core_crypto::prelude::ComputationBuffers;
use tfhe::core_crypto::fft_impl::fft64::math::fft::{Fft, FftView};
use dyn_stack::{PodStack, SizeOverflow, StackReq};


// /// This struct stores random vectors that were generated during
// /// the encryption of a lwe ciphertext or lwe compact ciphertext list.
// ///
// /// These are needed by the zero-knowledge proof
// pub struct SecretKeyRandomVectors<
//     Scalar: Encryptable<Uniform, Distribution>, 
//     // OutputCont: ContainerMut<Element = Scalar>,
//     // C: Container,
//     C::Element: UnsignedInteger,
//     > {
//     // This is the random mask
//     // mask: &mut LweMask<OutputCont>,
//     // mask: LweMask<OutputCont>,
//     // mask: LweMask<&mut [Scalar]>,
//     mask: LweMask<C: Container>,
//     // This is the noise
//     noise: Vec<Scalar>,
// }

pub fn encrypt_lwe_ciphertext_ret_noise<Scalar, NoiseDistribution, KeyCont, OutputCont, Gen>(
    lwe_secret_key: &LweSecretKey<KeyCont>,
    output: &mut LweCiphertext<OutputCont>,
    encoded: Plaintext<Scalar>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
// ) -> SecretKeyRandomVectors<Scalar, OutputCont>
// ) -> (LweMask<&mut [Scalar]>, Vec<Scalar>)
// ) -> Vec<Scalar>
// ) -> Scalar
) -> LweBody<Scalar>
where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    KeyCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert!(
        output.lwe_size().to_lwe_dimension() == lwe_secret_key.lwe_dimension(),
        "Mismatch between LweDimension of output ciphertext and input secret key. \
        Got {:?} in output, and {:?} in secret key.",
        output.lwe_size().to_lwe_dimension(),
        lwe_secret_key.lwe_dimension()
    );

    let (mut mask, mut body) = output.get_mut_mask_and_body();

    fill_lwe_mask_and_body_for_encryption_ret_noise::<Scalar, NoiseDistribution, KeyCont, OutputCont, Gen>(
        lwe_secret_key,
        &mut mask,
        &mut body,
        encoded,
        noise_distribution,
        generator,
    )
}

pub fn encrypt_lwe_ciphertext_list_ret_mask_and_noise<Scalar, NoiseDistribution, KeyCont, OutputCont, InputCont, Gen>(
    lwe_secret_key: &LweSecretKey<KeyCont>,
    output: &mut LweCiphertextList<OutputCont>,
    encoded: &PlaintextList<InputCont>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
) -> (Vec<LweMask<Vec<Scalar>>>, Vec<LweBody<Scalar>>)
where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    KeyCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert!(
        output.lwe_ciphertext_count().0 == encoded.plaintext_count().0,
        "Mismatch between number of output ciphertexts and input plaintexts. \
        Got {:?} plaintexts, and {:?} ciphertext.",
        encoded.plaintext_count(),
        output.lwe_ciphertext_count()
    );

    let gen_iter = generator
        .try_fork_from_config(output.encryption_fork_config(Uniform, noise_distribution))
        .unwrap();

    let mut new_ciphertext_modulus = CiphertextModulus::<Scalar>::new_native();
    if !output.ciphertext_modulus().is_native_modulus() {
        new_ciphertext_modulus = CiphertextModulus::<Scalar>::new(output.ciphertext_modulus().get_custom_modulus());
    }
    let mut noise_vector = vec![
        LweBody::new(Scalar::ZERO, new_ciphertext_modulus);
        output.lwe_ciphertext_count().0
    ];
    let mut mask_vector = vec![
        LweMask::from_container(
            vec![
                Scalar::ZERO; 
                output.lwe_size().to_lwe_dimension().0
            ], 
            new_ciphertext_modulus);
        output.lwe_ciphertext_count().0
    ];
    for ((((encoded_plaintext_ref, mut ciphertext), mut loop_generator), mask_entry), noise_entry) in
        encoded.iter().zip(output.iter_mut()).zip(gen_iter).zip(mask_vector.iter_mut()).zip(noise_vector.iter_mut())
    {
        noise_entry.data = encrypt_lwe_ciphertext_ret_noise(
            lwe_secret_key,
            &mut ciphertext,
            encoded_plaintext_ref.into(),
            noise_distribution,
            &mut loop_generator,
        ).data;
        mask_entry.as_mut().copy_from_slice(ciphertext.get_mask().as_ref());
    }

    (mask_vector, noise_vector)
}

pub fn fill_lwe_mask_and_body_for_encryption_ret_noise<Scalar, NoiseDistribution, KeyCont, OutputCont, Gen>(
    lwe_secret_key: &LweSecretKey<KeyCont>,
    output_mask: &mut LweMask<&mut [Scalar]>, // Changed to match type from get_mut_mask_and_body
    // output_mask: &mut LweMask<OutputCont>,
    output_body: &mut LweBodyRefMut<Scalar>,
    encoded: Plaintext<Scalar>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
// ) -> SecretKeyRandomVectors<Scalar, OutputCont>
// ) -> (LweMask<&mut [Scalar]>, Vec<Scalar>)
// ) -> Vec<Scalar>
// ) -> Scalar
) -> LweBody<Scalar>
where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    KeyCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert_eq!(
        output_mask.ciphertext_modulus(),
        output_body.ciphertext_modulus(),
        "Mismatched moduli between mask ({:?}) and body ({:?})",
        output_mask.ciphertext_modulus(),
        output_body.ciphertext_modulus()
    );

    let ciphertext_modulus = output_mask.ciphertext_modulus();

    if !ciphertext_modulus.is_compatible_with_native_modulus() {
        println!("NOT IMPLEMENTED: ciphertext_modulus NOT compatible with native modulus case");
    }
    fill_lwe_mask_and_body_for_encryption_native_mod_compatible_ret_noise::<Scalar, NoiseDistribution, KeyCont, OutputCont, Gen>(
        lwe_secret_key,
        output_mask,
        output_body,
        encoded,
        noise_distribution,
        generator,
    )

}

pub fn fill_lwe_mask_and_body_for_encryption_native_mod_compatible_ret_noise<
    Scalar,
    NoiseDistribution,
    KeyCont,
    OutputCont,
    Gen,
>(
    lwe_secret_key: &LweSecretKey<KeyCont>,
    output_mask: &mut LweMask<&mut [Scalar]>, // Changed to match type from get_mut_mask_and_body
    // output_mask: &mut LweMask<OutputCont>,
    output_body: &mut LweBodyRefMut<Scalar>,
    encoded: Plaintext<Scalar>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
// ) -> SecretKeyRandomVectors<Scalar, OutputCont>
// ) -> (LweMask<&mut [Scalar]>, Vec<Scalar>)
// ) -> Vec<Scalar>
// ) -> Scalar
) -> LweBody<Scalar>
where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    KeyCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert_eq!(
        output_mask.ciphertext_modulus(),
        output_body.ciphertext_modulus(),
        "Mismatched moduli between mask ({:?}) and body ({:?})",
        output_mask.ciphertext_modulus(),
        output_body.ciphertext_modulus()
    );

    let ciphertext_modulus = output_mask.ciphertext_modulus();

    assert!(ciphertext_modulus.is_compatible_with_native_modulus());

    // generate a randomly uniform mask
    generator
        .fill_slice_with_random_uniform_mask_custom_mod(output_mask.as_mut(), ciphertext_modulus);

    // generate an error from the given noise_distribution
    let mut noise =
        generator.random_noise_from_distribution_custom_mod(noise_distribution, ciphertext_modulus);
    // compute the multisum between the secret key and the mask
    let mask_key_dot_product =
        slice_wrapping_dot_product(output_mask.as_ref(), lwe_secret_key.as_ref());

    // Store sum(ai * si) + delta * m + e in the body
    *output_body.data = mask_key_dot_product
        .wrapping_add(encoded.0)
        .wrapping_add(noise);

    match ciphertext_modulus.kind() {
        CiphertextModulusKind::Native => (),
        CiphertextModulusKind::NonNativePowerOfTwo => {
            // Manage power of 2 encoding to map to the native case
            let torus_scaling = ciphertext_modulus.get_power_of_two_scaling_to_native_torus();
            slice_wrapping_scalar_mul_assign(output_mask.as_mut(), torus_scaling);
            *output_body.data = (*output_body.data).wrapping_mul(torus_scaling);
            // Scale noise returned
            noise = noise.wrapping_mul(torus_scaling);
        }
        CiphertextModulusKind::Other => unreachable!(),
    };
    // SecretKeyRandomVectors {
    //     mask: *output_mask,
    //     noise: vec![noise]
    // }

    // noise
    LweBody::new(noise, ciphertext_modulus)
}

pub fn encrypt_lwe_ciphertext_deterministic<Scalar, NoiseDistribution, KeyCont, OutputCont, Gen>(
    lwe_secret_key: &LweSecretKey<KeyCont>,
    output: &mut LweCiphertext<OutputCont>,
    encoded: Plaintext<Scalar>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
    mask: &LweMask<Vec<Scalar>>,
    // mask: &LweMask<&[Scalar]>,
    // noise: Scalar,
    noise: &LweBody<Scalar>,
) where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    KeyCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert!(
        output.lwe_size().to_lwe_dimension() == lwe_secret_key.lwe_dimension(),
        "Mismatch between LweDimension of output ciphertext and input secret key. \
        Got {:?} in output, and {:?} in secret key.",
        output.lwe_size().to_lwe_dimension(),
        lwe_secret_key.lwe_dimension()
    );

    let (mut output_mask, mut output_body) = output.get_mut_mask_and_body();

    fill_lwe_mask_and_body_for_encryption_deterministic(
        lwe_secret_key,
        &mut output_mask,
        &mut output_body,
        encoded,
        noise_distribution,
        generator,
        &mask,
        &noise,
    );
}

pub fn encrypt_lwe_ciphertext_list_deterministic<Scalar, NoiseDistribution, KeyCont, OutputCont, InputCont, Gen>(
    lwe_secret_key: &LweSecretKey<KeyCont>,
    output: &mut LweCiphertextList<OutputCont>,
    encoded: &PlaintextList<InputCont>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
    mask_vector: &Vec<LweMask<Vec<Scalar>>>,
    noise_vector: &Vec<LweBody<Scalar>>,
)
// ) -> (Vec<LweMask<Vec<Scalar>>>, Vec<LweBody<Scalar>>)
where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    KeyCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert!(
        output.lwe_ciphertext_count().0 == encoded.plaintext_count().0,
        "Mismatch between number of output ciphertexts and input plaintexts. \
        Got {:?} plaintexts, and {:?} ciphertext.",
        encoded.plaintext_count(),
        output.lwe_ciphertext_count()
    );

    let gen_iter = generator
        .try_fork_from_config(output.encryption_fork_config(Uniform, noise_distribution))
        .unwrap();

    // let mut new_ciphertext_modulus = CiphertextModulus::<Scalar>::new_native();
    // if !output.ciphertext_modulus().is_native_modulus() {
    //     new_ciphertext_modulus = CiphertextModulus::<Scalar>::new(output.ciphertext_modulus().get_custom_modulus());
    // }
    // let mut noise_vector = vec![
    //     LweBody::new(Scalar::ZERO, new_ciphertext_modulus);
    //     output.lwe_ciphertext_count().0
    // ];
    // let mut mask_vector = vec![
    //     LweMask::from_container(
    //         vec![
    //             Scalar::ZERO; 
    //             output.lwe_size().to_lwe_dimension().0
    //         ], 
    //         new_ciphertext_modulus);
    //     output.lwe_ciphertext_count().0
    // ];
    for ((((encoded_plaintext_ref, mut ciphertext), mut loop_generator), mask_entry), noise_entry) in
        encoded.iter().zip(output.iter_mut()).zip(gen_iter).zip(mask_vector.iter()).zip(noise_vector.iter())
    {
        // noise_entry.data = encrypt_lwe_ciphertext_ret_noise(
        encrypt_lwe_ciphertext_deterministic(
            lwe_secret_key,
            &mut ciphertext,
            encoded_plaintext_ref.into(),
            noise_distribution,
            &mut loop_generator,
            mask_entry,
            noise_entry,
        );
        // ).data;
        // mask_entry.as_mut().copy_from_slice(ciphertext.get_mask().as_ref());
    }

    // (mask_vector, noise_vector)
}

pub fn fill_lwe_mask_and_body_for_encryption_deterministic<Scalar, NoiseDistribution, KeyCont, OutputCont, Gen>(
    lwe_secret_key: &LweSecretKey<KeyCont>,
    output_mask: &mut LweMask<OutputCont>,
    output_body: &mut LweBodyRefMut<Scalar>,
    encoded: Plaintext<Scalar>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
    mask: &LweMask<Vec<Scalar>>,
    // mask: &LweMask<&[Scalar]>,
    // noise: Scalar,
    noise: &LweBody<Scalar>,
) where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    KeyCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert_eq!(
        output_mask.ciphertext_modulus(),
        output_body.ciphertext_modulus(),
        "Mismatched moduli between mask ({:?}) and body ({:?})",
        output_mask.ciphertext_modulus(),
        output_body.ciphertext_modulus()
    );

    let ciphertext_modulus = output_mask.ciphertext_modulus();

    if !ciphertext_modulus.is_compatible_with_native_modulus() {
        println!("NOT IMPLEMENTED: ciphertext_modulus NOT compatible with native modulus case");
    }
    fill_lwe_mask_and_body_for_encryption_native_mod_compatible_deterministic(
        lwe_secret_key,
        output_mask,
        output_body,
        encoded,
        noise_distribution,
        generator,
        &mask, 
        &noise,
    );
}

pub fn fill_lwe_mask_and_body_for_encryption_native_mod_compatible_deterministic<
    Scalar,
    NoiseDistribution,
    KeyCont,
    OutputCont,
    Gen,
>(
    lwe_secret_key: &LweSecretKey<KeyCont>,
    output_mask: &mut LweMask<OutputCont>,
    output_body: &mut LweBodyRefMut<Scalar>,
    encoded: Plaintext<Scalar>,
    _noise_distribution: NoiseDistribution,
    _generator: &mut EncryptionRandomGenerator<Gen>,
    mask: &LweMask<Vec<Scalar>>,
    // mask: &LweMask<&[Scalar]>,
    // noise: Scalar,
    noise: &LweBody<Scalar>,
) where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    KeyCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert_eq!(
        output_mask.ciphertext_modulus(),
        output_body.ciphertext_modulus(),
        "Mismatched moduli between mask ({:?}) and body ({:?})",
        output_mask.ciphertext_modulus(),
        output_body.ciphertext_modulus()
    );

    let ciphertext_modulus = output_mask.ciphertext_modulus();

    assert!(ciphertext_modulus.is_compatible_with_native_modulus());

    // Assign output_mask to be the deterministically specified mask
    output_mask.as_mut().copy_from_slice(mask.as_ref());

    // compute the multisum between the secret key and the mask
    let mask_key_dot_product =
        slice_wrapping_dot_product(output_mask.as_ref(), lwe_secret_key.as_ref());

    // Store sum(ai * si) + delta * m + e in the body
    // NOTE: this is done in two steps (1) and (2) below. This is because of the following assumption.
    // ASSUMPTION: mask and noise are already scaled if CiphertextModulusKind::NonNativePowerOfTwo case is satisfied below.
    // So, we don't want to multiply mask and noise with torus_scaling twice. Only msg (encoded.0) is scaled in (1).
    // (1)
    *output_body.data = encoded.0;
    // *output_body.data = mask_key_dot_product
    //     .wrapping_add(encoded.0)
    //     .wrapping_add(noise);

    match ciphertext_modulus.kind() {
        CiphertextModulusKind::Native => (),
        CiphertextModulusKind::NonNativePowerOfTwo => {
            // Manage power of 2 encoding to map to the native case
            let torus_scaling = ciphertext_modulus.get_power_of_two_scaling_to_native_torus();
            // NOTE: no need to scale output_mask. ASSUMPTION: 'mask' is already scaled.
            // slice_wrapping_scalar_mul_assign(output_mask.as_mut(), torus_scaling);
            *output_body.data = (*output_body.data).wrapping_mul(torus_scaling);
        }
        CiphertextModulusKind::Other => unreachable!(),
    };
    // (2)
    *output_body.data = (*output_body.data).wrapping_add(mask_key_dot_product).wrapping_add(noise.data);
    // *output_body.data = (*output_body.data).wrapping_add(mask_key_dot_product).wrapping_add(noise);
}

pub fn encrypt_glwe_ciphertext_ret_noise<Scalar, NoiseDistribution, KeyCont, InputCont, OutputCont, Gen>(
    glwe_secret_key: &GlweSecretKey<KeyCont>,
    output_glwe_ciphertext: &mut GlweCiphertext<OutputCont>,
    input_plaintext_list: &PlaintextList<InputCont>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
// ) -> Vec<Scalar>
// ) -> GlweBody<BodyCont>
// ) -> GlweBody<NoiseCont>
) -> GlweBody<Vec<Scalar>>
where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    KeyCont: Container<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
    // BodyCont: ContainerMut<Element = Scalar>,
    // NoiseCont: ContainerMut<Element = Scalar>,
    // NoiseCont: Container<Element = Scalar>,
{
    assert!(
        output_glwe_ciphertext.polynomial_size().0 == input_plaintext_list.plaintext_count().0,
        "Mismatch between PolynomialSize of output ciphertext PlaintextCount of input. \
    Got {:?} in output, and {:?} in input.",
        output_glwe_ciphertext.polynomial_size(),
        input_plaintext_list.plaintext_count()
    );
    assert!(
        output_glwe_ciphertext.glwe_size().to_glwe_dimension() == glwe_secret_key.glwe_dimension(),
        "Mismatch between GlweDimension of output ciphertext and input secret key. \
        Got {:?} in output, and {:?} in secret key.",
        output_glwe_ciphertext.glwe_size().to_glwe_dimension(),
        glwe_secret_key.glwe_dimension()
    );
    assert!(
        output_glwe_ciphertext.polynomial_size() == glwe_secret_key.polynomial_size(),
        "Mismatch between PolynomialSize of output ciphertext and input secret key. \
        Got {:?} in output, and {:?} in secret key.",
        output_glwe_ciphertext.polynomial_size(),
        glwe_secret_key.polynomial_size()
    );

    let (mut mask, mut body) = output_glwe_ciphertext.get_mut_mask_and_body();

    fill_glwe_mask_and_body_for_encryption_ret_noise(
        glwe_secret_key,
        &mut mask,
        &mut body,
        input_plaintext_list,
        noise_distribution,
        generator,
    )
}

pub fn fill_glwe_mask_and_body_for_encryption_ret_noise<
    Scalar,
    NoiseDistribution,
    KeyCont,
    InputCont,
    BodyCont,
    MaskCont,
    Gen,
    // NoiseCont,
>(
    glwe_secret_key: &GlweSecretKey<KeyCont>,
    output_mask: &mut GlweMask<MaskCont>,
    output_body: &mut GlweBody<BodyCont>,
    encoded: &PlaintextList<InputCont>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
// ) -> Vec<Scalar>
// ) -> GlweBody<BodyCont>
// ) -> GlweBody<NoiseCont>
) -> GlweBody<Vec<Scalar>>
where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    KeyCont: Container<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    BodyCont: ContainerMut<Element = Scalar>,
    MaskCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
    // NoiseCont: ContainerMut<Element = Scalar>,
    // NoiseCont: Container<Element = Scalar>,
{
    let ciphertext_modulus = output_body.ciphertext_modulus();

    if !ciphertext_modulus.is_compatible_with_native_modulus() {
        println!("NOT IMPLEMENTED: ciphertext_modulus NOT compatible with native modulus case");
    }

    fill_glwe_mask_and_body_for_encryption_native_mod_compatible_ret_noise(
        glwe_secret_key,
        output_mask,
        output_body,
        encoded,
        noise_distribution,
        generator,
    )
}

pub fn fill_glwe_mask_and_body_for_encryption_native_mod_compatible_ret_noise<
    Scalar,
    NoiseDistribution,
    KeyCont,
    InputCont,
    BodyCont,
    MaskCont,
    Gen,
    // NoiseCont,
>(
    glwe_secret_key: &GlweSecretKey<KeyCont>,
    output_mask: &mut GlweMask<MaskCont>,
    output_body: &mut GlweBody<BodyCont>,
    encoded: &PlaintextList<InputCont>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
// ) -> Vec<Scalar>
// ) -> GlweBody<BodyCont>
// ) -> GlweBody<NoiseCont>
// ) -> GlweBody<Container<Scalar>>
) -> GlweBody<Vec<Scalar>>
where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    KeyCont: Container<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    BodyCont: ContainerMut<Element = Scalar>,
    MaskCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
    // NoiseCont: ContainerMut<Element = Scalar>,
{
    assert_eq!(
        output_mask.ciphertext_modulus(),
        output_body.ciphertext_modulus()
    );

    let ciphertext_modulus = output_body.ciphertext_modulus();

    assert!(ciphertext_modulus.is_compatible_with_native_modulus());

    // output_mask = random value
    generator
        .fill_slice_with_random_uniform_mask_custom_mod(output_mask.as_mut(), ciphertext_modulus);
    // output_body = sampled noise
    generator.fill_slice_with_random_noise_from_distribution_custom_mod(
        output_body.as_mut(),
        noise_distribution,
        ciphertext_modulus,
    );
    let mut noise = output_body.as_ref().to_vec();
    // let mut noise = output_body.as_mut();
    // let mut noise = output_body.clone();
    // let mut noise = GlweBody::from_container(output_body.as_ref(), output_body.ciphertext_modulus());

    polynomial_wrapping_add_assign(
        &mut output_body.as_mut_polynomial(),
        &encoded.as_polynomial(),
    );

    if !ciphertext_modulus.is_native_modulus() {
        let torus_scaling = ciphertext_modulus.get_power_of_two_scaling_to_native_torus();
        slice_wrapping_scalar_mul_assign(output_mask.as_mut(), torus_scaling);
        slice_wrapping_scalar_mul_assign(output_body.as_mut(), torus_scaling);
        // slice_wrapping_scalar_mul_assign(noise.as_mut(), torus_scaling);
        slice_wrapping_scalar_mul_assign(&mut noise, torus_scaling);
    }    

    polynomial_wrapping_add_multisum_assign(
        &mut output_body.as_mut_polynomial(),
        &output_mask.as_polynomial_list(),
        &glwe_secret_key.as_polynomial_list(),
    );

    // noise
    GlweBody::from_container(noise, ciphertext_modulus)
}

pub fn encrypt_glwe_ciphertext_deterministic<Scalar, NoiseDistribution, KeyCont, InputCont, OutputCont, Gen>(
    glwe_secret_key: &GlweSecretKey<KeyCont>,
    output_glwe_ciphertext: &mut GlweCiphertext<OutputCont>,
    input_plaintext_list: &PlaintextList<InputCont>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
    deterministic_mask: &GlweMask<&[Scalar]>,
    // deterministic_mask: &GlweMask<Vec<Scalar>>,
    deterministic_noise: &GlweBody<Vec<Scalar>>,
) where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    KeyCont: Container<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert!(
        output_glwe_ciphertext.polynomial_size().0 == input_plaintext_list.plaintext_count().0,
        "Mismatch between PolynomialSize of output ciphertext PlaintextCount of input. \
    Got {:?} in output, and {:?} in input.",
        output_glwe_ciphertext.polynomial_size(),
        input_plaintext_list.plaintext_count()
    );
    assert!(
        output_glwe_ciphertext.glwe_size().to_glwe_dimension() == glwe_secret_key.glwe_dimension(),
        "Mismatch between GlweDimension of output ciphertext and input secret key. \
        Got {:?} in output, and {:?} in secret key.",
        output_glwe_ciphertext.glwe_size().to_glwe_dimension(),
        glwe_secret_key.glwe_dimension()
    );
    assert!(
        output_glwe_ciphertext.polynomial_size() == glwe_secret_key.polynomial_size(),
        "Mismatch between PolynomialSize of output ciphertext and input secret key. \
        Got {:?} in output, and {:?} in secret key.",
        output_glwe_ciphertext.polynomial_size(),
        glwe_secret_key.polynomial_size()
    );

    let (mut mask, mut body) = output_glwe_ciphertext.get_mut_mask_and_body();

    fill_glwe_mask_and_body_for_encryption_deterministic(
        glwe_secret_key,
        &mut mask,
        &mut body,
        input_plaintext_list,
        noise_distribution,
        generator,
        deterministic_mask,
        deterministic_noise,
    );
}

pub fn fill_glwe_mask_and_body_for_encryption_deterministic<
    Scalar,
    NoiseDistribution,
    KeyCont,
    InputCont,
    BodyCont,
    MaskCont,
    Gen,
>(
    glwe_secret_key: &GlweSecretKey<KeyCont>,
    output_mask: &mut GlweMask<MaskCont>,
    output_body: &mut GlweBody<BodyCont>,
    encoded: &PlaintextList<InputCont>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
    deterministic_mask: &GlweMask<&[Scalar]>,
    // deterministic_mask: &GlweMask<Vec<Scalar>>,
    deterministic_noise: &GlweBody<Vec<Scalar>>,
) where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    KeyCont: Container<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    BodyCont: ContainerMut<Element = Scalar>,
    MaskCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    let ciphertext_modulus = output_body.ciphertext_modulus();

    if !ciphertext_modulus.is_compatible_with_native_modulus() {
        println!("NOT IMPLEMENTED: ciphertext_modulus NOT compatible with native modulus case");
    }

    fill_glwe_mask_and_body_for_encryption_native_mod_compatible_deterministic(
        glwe_secret_key,
        output_mask,
        output_body,
        encoded,
        noise_distribution,
        generator,
        deterministic_mask,
        deterministic_noise,
    )
}

pub fn fill_glwe_mask_and_body_for_encryption_native_mod_compatible_deterministic<
    Scalar,
    NoiseDistribution,
    KeyCont,
    InputCont,
    BodyCont,
    MaskCont,
    Gen,
>(
    glwe_secret_key: &GlweSecretKey<KeyCont>,
    output_mask: &mut GlweMask<MaskCont>,
    output_body: &mut GlweBody<BodyCont>,
    encoded: &PlaintextList<InputCont>,
    _noise_distribution: NoiseDistribution,
    _generator: &mut EncryptionRandomGenerator<Gen>,
    deterministic_mask: &GlweMask<&[Scalar]>,
    // deterministic_mask: &GlweMask<Vec<Scalar>>,
    deterministic_noise: &GlweBody<Vec<Scalar>>,
) where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    KeyCont: Container<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    BodyCont: ContainerMut<Element = Scalar>,
    MaskCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert_eq!(
        output_mask.ciphertext_modulus(),
        output_body.ciphertext_modulus()
    );

    let ciphertext_modulus = output_body.ciphertext_modulus();

    assert!(ciphertext_modulus.is_compatible_with_native_modulus());

    // output_mask = deterministic_mask
    output_mask.as_mut().copy_from_slice(deterministic_mask.as_ref());    
        // generator
        //     .fill_slice_with_random_uniform_mask_custom_mod(output_mask.as_mut(), ciphertext_modulus);
    // output_body =  deterministic_noise
        // generator.fill_slice_with_random_noise_from_distribution_custom_mod(
        //     output_body.as_mut(),
        //     noise_distribution,
        //     ciphertext_modulus,
        // );

    polynomial_wrapping_add_assign(
        &mut output_body.as_mut_polynomial(),
        &encoded.as_polynomial(),
    );

    if !ciphertext_modulus.is_native_modulus() {
        let torus_scaling = ciphertext_modulus.get_power_of_two_scaling_to_native_torus();
        // NOTE: no need to scale mask. ASSUMPTION: deterministic_mask is already scaled.
        // slice_wrapping_scalar_mul_assign(output_mask.as_mut(), torus_scaling);
        slice_wrapping_scalar_mul_assign(output_body.as_mut(), torus_scaling);
    }
    slice_wrapping_add_assign(output_body.as_mut(), deterministic_noise.as_ref());
    // output_body.as_mut().copy_from_slice(deterministic_noise.as_ref());    

    polynomial_wrapping_add_multisum_assign(
        &mut output_body.as_mut_polynomial(),
        &output_mask.as_polynomial_list(),
        &glwe_secret_key.as_polynomial_list(),
    );
}

pub fn encrypt_constant_seeded_ggsw_ciphertext_ret_mask_and_noise<
    Scalar,
    NoiseDistribution,
    KeyCont,
    OutputCont,
    NoiseSeeder,
>(
    glwe_secret_key: &GlweSecretKey<KeyCont>,
    output: &mut SeededGgswCiphertext<OutputCont>,
    cleartext: Cleartext<Scalar>,
    noise_distribution: NoiseDistribution,
    noise_seeder: &mut NoiseSeeder,
// )
// ) -> Vec<Vec<Scalar>>
// ) -> (Vec<GlweMask<Vec<Scalar>>>, Vec<Vec<Scalar>>)
) -> (Vec<GlweMask<Vec<Scalar>>>, Vec<GlweBody<Vec<Scalar>>>)
where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    KeyCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    // Maybe Sized allows to pass Box<dyn Seeder>.
    NoiseSeeder: Seeder + ?Sized,
{
    assert!(
        output.polynomial_size() == glwe_secret_key.polynomial_size(),
        "Mismatch between polynomial sizes of output ciphertexts and input secret key. \
        Got {:?} in output, and {:?} in secret key.",
        output.polynomial_size(),
        glwe_secret_key.polynomial_size()
    );

    assert!(
        output.glwe_size().to_glwe_dimension() == glwe_secret_key.glwe_dimension(),
        "Mismatch between GlweDimension of output ciphertexts and input secret key. \
        Got {:?} in output, and {:?} in secret key.",
        output.glwe_size().to_glwe_dimension(),
        glwe_secret_key.glwe_dimension()
    );

    let mut generator = EncryptionRandomGenerator::<DefaultRandomGenerator>::new(
        output.compression_seed().seed,
        noise_seeder,
    );

    encrypt_constant_seeded_ggsw_ciphertext_with_existing_generator_ret_mask_and_noise(
        glwe_secret_key,
        output,
        cleartext,
        noise_distribution,
        &mut generator,
    )
}

pub fn encrypt_constant_seeded_ggsw_ciphertext_with_existing_generator_ret_mask_and_noise<
    Scalar,
    NoiseDistribution,
    KeyCont,
    OutputCont,
    Gen,
>(
    glwe_secret_key: &GlweSecretKey<KeyCont>,
    output: &mut SeededGgswCiphertext<OutputCont>,
    cleartext: Cleartext<Scalar>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
// )
// ) -> Vec<Vec<Scalar>>
// ) -> (Vec<GlweMask<Vec<Scalar>>>, Vec<Vec<Scalar>>)
) -> (Vec<GlweMask<Vec<Scalar>>>, Vec<GlweBody<Vec<Scalar>>>)
where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    KeyCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    // Generators used to have same sequential and parallel key generation
    let gen_iter = generator
        .try_fork_from_config(output.encryption_fork_config(Uniform, noise_distribution))
        .expect("Failed to split generator into ggsw levels");

    let decomp_base_log = output.decomposition_base_log();
    let decomp_level_count = output.decomposition_level_count();
    let polynomial_size = output.polynomial_size();
    let glwe_size = output.glwe_size();
    let ciphertext_modulus = output.ciphertext_modulus();
    // let mut noise_vector = vec![Scalar::ZERO; ggsw_ciphertext_encryption_noise_sample_count(glwe_size, polynomial_size, decomp_level_count).0];
    // let mut noise_vector = vec![vec![Scalar::ZERO; polynomial_size.0]; 
    //                             glwe_size.0 * decomp_level_count.0];
    let mut noise_vector = vec![GlweBody::from_container(
                                    vec![
                                        Scalar::ZERO;
                                        polynomial_size.0
                                    ],
                                    // polynomial_size,
                                    ciphertext_modulus,
                                ); 
                               glwe_size.0 * decomp_level_count.0];
    let mut mask_vector = vec![GlweMask::from_container(
                                    vec![
                                        Scalar::ZERO;
                                        glwe_ciphertext_mask_size(
                                            glwe_size.to_glwe_dimension(),
                                            polynomial_size
                                        )
                                    ],
                                    polynomial_size,
                                    ciphertext_modulus,
                                ); 
                               glwe_size.0 * decomp_level_count.0];

    for (output_index, (mut level_matrix, mut loop_generator)) in
        output.iter_mut().zip(gen_iter).enumerate()
    {
        println!("output_index: {:?}", output_index);
        // println!("level_matrix: {:?}", level_matrix);
        let decomp_level = DecompositionLevel(decomp_level_count.0 - output_index);
        let factor = ggsw_encryption_multiplicative_factor(
            ciphertext_modulus,
            decomp_level,
            decomp_base_log,
            cleartext,
        );

        // We iterate over the rows of the level matrix, the last row needs special treatment
        let gen_iter = loop_generator
            .try_fork_from_config(level_matrix.encryption_fork_config(Uniform, noise_distribution))
            .expect("Failed to split generator into glwe");

        let last_row_index = level_matrix.glwe_size().0 - 1;

        for ((row_index, mut row_as_glwe), mut loop_generator) in level_matrix
            .as_mut_seeded_glwe_list()
            .iter_mut()
            .enumerate()
            .zip(gen_iter)
        {
            println!("row_index: {:?}", row_index);
            // let mut row_noise_vector = vec![Scalar::ZERO; polynomial_size.0];
            // let mut row_mask = GlweMask::from_container(
            //     vec![
            //         Scalar::ZERO;
            //         glwe_ciphertext_mask_size(
            //             row_as_glwe.glwe_size().to_glwe_dimension(),
            //             row_as_glwe.polynomial_size()
            //         )
            //     ],
            //     row_as_glwe.polynomial_size(),
            //     row_as_glwe.ciphertext_modulus(),
            // );
            (mask_vector[(last_row_index+1) * output_index + row_index], noise_vector[(last_row_index+1) * output_index + row_index]) = encrypt_constant_seeded_ggsw_level_matrix_row_ret_mask_and_noise(
                glwe_secret_key,
                (row_index, last_row_index),
                factor,
                &mut row_as_glwe,
                noise_distribution,
                &mut loop_generator,
            );
            // println!("row_as_glwe: {:?}", row_as_glwe);
            // println!("row_noise_vector.len(): {:?}", noise_vector[(last_row_index+1) * output_index + row_index].len());
            // println!("row_mask.glwe_dimension(): {:?}, row_mask.polynomial_size(): {:?}", mask_vector[(last_row_index+1) * output_index + row_index].glwe_dimension(), mask_vector[(last_row_index+1) * output_index + row_index].polynomial_size());

            // println!("noise_vector: {:?}", noise_vector);
            // println!("mask_vector: {:?}", mask_vector);
            // let start_index = ((last_row_index+1) * output_index + row_index) * polynomial_size.0;
            // let end_index = start_index + row_noise_vector.len();
            // noise_vector[start_index..end_index].copy_from_slice(&row_noise_vector);
            // // println!("noise_vector: {:?}", noise_vector);
        }
        // println!("level_matrix: {:?}", level_matrix.as_seeded_glwe_list());

    }
    (mask_vector, noise_vector)
    // noise_vector
}

fn encrypt_constant_seeded_ggsw_level_matrix_row_update_mask_and_noise<
// fn encrypt_constant_seeded_ggsw_level_matrix_row<
    Scalar,
    NoiseDistribution,
    KeyCont,
    OutputCont,
    Gen,
    // C,
>(
    glwe_secret_key: &GlweSecretKey<KeyCont>,
    (row_index, last_row_index): (usize, usize),
    factor: Scalar,
    row_as_glwe: &mut SeededGlweCiphertext<OutputCont>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
    mask_vector: &mut GlweMask<Vec<Scalar>>,
    // noise_vector: &mut Vec<Scalar>,
    noise_vector: &mut GlweBody<Vec<Scalar>>,
)
where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    KeyCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    // C: Container<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    (*mask_vector, *noise_vector) = encrypt_constant_seeded_ggsw_level_matrix_row_ret_mask_and_noise(
                                        glwe_secret_key,
                                        (row_index, last_row_index),
                                        factor,
                                        row_as_glwe,
                                        noise_distribution,
                                        generator,
                                    );
}

fn encrypt_constant_seeded_ggsw_level_matrix_row_ret_mask_and_noise<
// fn encrypt_constant_seeded_ggsw_level_matrix_row<
    Scalar,
    NoiseDistribution,
    KeyCont,
    OutputCont,
    Gen,
    // C,
>(
    glwe_secret_key: &GlweSecretKey<KeyCont>,
    (row_index, last_row_index): (usize, usize),
    factor: Scalar,
    row_as_glwe: &mut SeededGlweCiphertext<OutputCont>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
// ) -> Vec<Scalar>
// ) -> (GlweMask<Vec<Scalar>>, Vec<Scalar>)
) -> (GlweMask<Vec<Scalar>>, GlweBody<Vec<Scalar>>)
where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    KeyCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    // C: Container<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    if row_index < last_row_index {
        // Not the last row
        let sk_poly_list = glwe_secret_key.as_polynomial_list();
        let sk_poly = sk_poly_list.get(row_index);

        // Copy the key polynomial to the output body, to avoid allocating a temporary buffer
        let mut body = row_as_glwe.get_mut_body();
        body.as_mut().copy_from_slice(sk_poly.as_ref());

        let ciphertext_modulus = body.ciphertext_modulus();

        match ciphertext_modulus.kind() {
            CiphertextModulusKind::Other => slice_wrapping_scalar_mul_assign_custom_mod(
                body.as_mut(),
                factor,
                ciphertext_modulus.get_custom_modulus().cast_into(),
            ),
            CiphertextModulusKind::Native | CiphertextModulusKind::NonNativePowerOfTwo => {
                slice_wrapping_scalar_mul_assign(body.as_mut(), factor)
            }
        }
    } else {
        // The last row needs a slightly different treatment
        let mut body = row_as_glwe.get_mut_body();
        let ciphertext_modulus = body.ciphertext_modulus();

        body.as_mut().fill(Scalar::ZERO);
        let encoded = match ciphertext_modulus.kind() {
            CiphertextModulusKind::Other => {
                factor.wrapping_neg_custom_mod(ciphertext_modulus.get_custom_modulus().cast_into())
            }
            CiphertextModulusKind::Native | CiphertextModulusKind::NonNativePowerOfTwo => {
                factor.wrapping_neg()
            }
        };
        body.as_mut()[0] = encoded;
    }
    encrypt_seeded_glwe_ciphertext_assign_with_existing_generator_ret_noise(
        glwe_secret_key,
        row_as_glwe,
        noise_distribution,
        generator,
    )
}

pub fn encrypt_seeded_glwe_ciphertext_assign_with_existing_generator_ret_noise<
    Scalar,
    NoiseDistribution,
    KeyCont,
    OutputCont,
    Gen,
    // C,
>(
    glwe_secret_key: &GlweSecretKey<KeyCont>,
    output: &mut SeededGlweCiphertext<OutputCont>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
// ) -> Vec<Scalar>
// ) -> (GlweMask<Vec<Scalar>>, Vec<Scalar>)
) -> (GlweMask<Vec<Scalar>>, GlweBody<Vec<Scalar>>)
where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    KeyCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    // C: Container<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert!(
        output.glwe_size().to_glwe_dimension() == glwe_secret_key.glwe_dimension(),
        "Mismatch between GlweDimension of output ciphertext and input secret key. \
        Got {:?} in output, and {:?} in secret key.",
        output.glwe_size().to_glwe_dimension(),
        glwe_secret_key.glwe_dimension()
    );
    assert!(
        output.polynomial_size() == glwe_secret_key.polynomial_size(),
        "Mismatch between PolynomialSize of output ciphertext and input secret key. \
        Got {:?} in output, and {:?} in secret key.",
        output.polynomial_size(),
        glwe_secret_key.polynomial_size()
    );

    let mut mask = GlweMask::from_container(
        vec![
            Scalar::ZERO;
            glwe_ciphertext_mask_size(
                output.glwe_size().to_glwe_dimension(),
                output.polynomial_size()
            )
        ],
        output.polynomial_size(),
        output.ciphertext_modulus(),
    );
    let mut body = output.get_mut_body();

    let noise = fill_glwe_mask_and_body_for_encryption_assign_ret_noise(
        glwe_secret_key,
        &mut mask,
        &mut body,
        noise_distribution,
        generator,
    );
    // noise
    (mask, noise)
}

pub fn fill_glwe_mask_and_body_for_encryption_assign_ret_noise<
    Scalar,
    NoiseDistribution,
    KeyCont,
    BodyCont,
    MaskCont,
    Gen,
>(
    glwe_secret_key: &GlweSecretKey<KeyCont>,
    output_mask: &mut GlweMask<MaskCont>,
    output_body: &mut GlweBody<BodyCont>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
// ) -> Vec<Scalar>
) -> GlweBody<Vec<Scalar>>
where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    KeyCont: Container<Element = Scalar>,
    BodyCont: ContainerMut<Element = Scalar>,
    MaskCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    let ciphertext_modulus = output_body.ciphertext_modulus();

    if !ciphertext_modulus.is_compatible_with_native_modulus() {
        println!("NOT IMPLEMENTED: ciphertext_modulus NOT compatible with native modulus case");
    }

    fill_glwe_mask_and_body_for_encryption_assign_native_mod_compatible_ret_noise(
        glwe_secret_key,
        output_mask,
        output_body,
        noise_distribution,
        generator,
    )
}

pub fn fill_glwe_mask_and_body_for_encryption_assign_native_mod_compatible_ret_noise<
    Scalar,
    NoiseDistribution,
    KeyCont,
    BodyCont,
    MaskCont,
    Gen,
>(
    glwe_secret_key: &GlweSecretKey<KeyCont>,
    output_mask: &mut GlweMask<MaskCont>,
    output_body: &mut GlweBody<BodyCont>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
// ) -> Vec<Scalar>
) -> GlweBody<Vec<Scalar>>
where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    KeyCont: Container<Element = Scalar>,
    BodyCont: ContainerMut<Element = Scalar>,
    MaskCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert_eq!(
        output_mask.ciphertext_modulus(),
        output_body.ciphertext_modulus(),
        "Mismatched moduli between output_mask ({:?}) and output_body ({:?})",
        output_mask.ciphertext_modulus(),
        output_body.ciphertext_modulus()
    );

    let ciphertext_modulus = output_body.ciphertext_modulus();

    assert!(ciphertext_modulus.is_compatible_with_native_modulus());

    // output_mask = random value
    generator
        .fill_slice_with_random_uniform_mask_custom_mod(output_mask.as_mut(), ciphertext_modulus);
    
    // msg_body = msg
    let msg_body = output_body.as_ref().to_vec();
    // output_body = msg + sampled noise
    generator.unsigned_integer_slice_wrapping_add_random_noise_from_distribution_custom_mod_assign(
        output_body.as_mut(),
        noise_distribution,
        ciphertext_modulus,
    );
    // noise = output_body - msg_body
    let mut noise = output_body.as_ref().to_vec();
    slice_wrapping_sub(&mut noise, output_body.as_ref(), &msg_body);

    if !ciphertext_modulus.is_native_modulus() {
        println!("ciphertext_modulus.is_native_modulus(): False");
        let torus_scaling = ciphertext_modulus.get_power_of_two_scaling_to_native_torus();
        slice_wrapping_scalar_mul_assign(output_mask.as_mut(), torus_scaling);
        slice_wrapping_scalar_mul_assign(output_body.as_mut(), torus_scaling);
        slice_wrapping_scalar_mul_assign(&mut noise, torus_scaling);
    }

    // println!("noise: {:?}", noise);
    // println!("output_mask: {:?}", output_mask.as_polynomial_list());
    // println!("glwe_secret_key: {:?}", glwe_secret_key.as_polynomial_list());

    // output_body = msg + sampled noise + output_mask * glwe_secret_key
    polynomial_wrapping_add_multisum_assign(
        &mut output_body.as_mut_polynomial(),
        &output_mask.as_polynomial_list(),
        &glwe_secret_key.as_polynomial_list(),
    );
    // println!("output_body: {:?}", output_body.as_polynomial());
    // Ensure that noise is not updated here.
    // println!("noise: {:?}", noise);
    // noise
    GlweBody::from_container(noise, ciphertext_modulus)

}

pub fn encrypt_constant_seeded_ggsw_ciphertext_deterministic<
    Scalar,
    NoiseDistribution,
    KeyCont,
    OutputCont,
    NoiseSeeder,
>(
    glwe_secret_key: &GlweSecretKey<KeyCont>,
    output: &mut SeededGgswCiphertext<OutputCont>,
    cleartext: Cleartext<Scalar>,
    noise_distribution: NoiseDistribution,
    noise_seeder: &mut NoiseSeeder,
    mask_vector: &Vec<GlweMask<Vec<Scalar>>>,
    // noise_vector: &Vec<Vec<Scalar>>,
    noise_vector: &Vec<GlweBody<Vec<Scalar>>>,

) where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    KeyCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    // Maybe Sized allows to pass Box<dyn Seeder>.
    NoiseSeeder: Seeder + ?Sized,
{
    assert!(
        output.polynomial_size() == glwe_secret_key.polynomial_size(),
        "Mismatch between polynomial sizes of output ciphertexts and input secret key. \
        Got {:?} in output, and {:?} in secret key.",
        output.polynomial_size(),
        glwe_secret_key.polynomial_size()
    );

    assert!(
        output.glwe_size().to_glwe_dimension() == glwe_secret_key.glwe_dimension(),
        "Mismatch between GlweDimension of output ciphertexts and input secret key. \
        Got {:?} in output, and {:?} in secret key.",
        output.glwe_size().to_glwe_dimension(),
        glwe_secret_key.glwe_dimension()
    );

    let mut generator = EncryptionRandomGenerator::<DefaultRandomGenerator>::new(
        output.compression_seed().seed,
        noise_seeder,
    );

    encrypt_constant_seeded_ggsw_ciphertext_with_existing_generator_deterministic(
        glwe_secret_key,
        output,
        cleartext,
        noise_distribution,
        &mut generator,
        mask_vector,
        noise_vector,
    );
}

pub fn encrypt_constant_seeded_ggsw_ciphertext_with_existing_generator_deterministic<
    Scalar,
    NoiseDistribution,
    KeyCont,
    OutputCont,
    Gen,
>(
    glwe_secret_key: &GlweSecretKey<KeyCont>,
    output: &mut SeededGgswCiphertext<OutputCont>,
    cleartext: Cleartext<Scalar>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
    mask_vector: &Vec<GlweMask<Vec<Scalar>>>,
    // noise_vector: &Vec<Vec<Scalar>>,
    noise_vector: &Vec<GlweBody<Vec<Scalar>>>,
) where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    KeyCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    // Generators used to have same sequential and parallel key generation
    let gen_iter = generator
        .try_fork_from_config(output.encryption_fork_config(Uniform, noise_distribution))
        .expect("Failed to split generator into ggsw levels");

    let decomp_base_log = output.decomposition_base_log();
    let decomp_level_count = output.decomposition_level_count();
    let ciphertext_modulus = output.ciphertext_modulus();

    for (output_index, (mut level_matrix, mut loop_generator)) in
        output.iter_mut().zip(gen_iter).enumerate()
    {
        let decomp_level = DecompositionLevel(decomp_level_count.0 - output_index);
        let factor = ggsw_encryption_multiplicative_factor(
            ciphertext_modulus,
            decomp_level,
            decomp_base_log,
            cleartext,
        );

        // We iterate over the rows of the level matrix, the last row needs special treatment
        let gen_iter = loop_generator
            .try_fork_from_config(level_matrix.encryption_fork_config(Uniform, noise_distribution))
            .expect("Failed to split generator into glwe");

        let last_row_index = level_matrix.glwe_size().0 - 1;

        for ((row_index, mut row_as_glwe), mut loop_generator) in level_matrix
            .as_mut_seeded_glwe_list()
            .iter_mut()
            .enumerate()
            .zip(gen_iter)
        {
            encrypt_constant_seeded_ggsw_level_matrix_row_deterministic(
                glwe_secret_key,
                (row_index, last_row_index),
                factor,
                &mut row_as_glwe,
                noise_distribution,
                &mut loop_generator,
                &mask_vector[(last_row_index+1) * output_index + row_index],
                &noise_vector[(last_row_index+1) * output_index + row_index],
            );
            // println!("row_as_glwe: {:?}", row_as_glwe);
        }
        // println!("level_matrix: {:?}", level_matrix.as_seeded_glwe_list());
    }
}

fn encrypt_constant_seeded_ggsw_level_matrix_row_deterministic<
    Scalar,
    NoiseDistribution,
    KeyCont,
    OutputCont,
    Gen,
>(
    glwe_secret_key: &GlweSecretKey<KeyCont>,
    (row_index, last_row_index): (usize, usize),
    factor: Scalar,
    row_as_glwe: &mut SeededGlweCiphertext<OutputCont>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
    deterministic_mask: &GlweMask<Vec<Scalar>>,
    deterministic_noise: &GlweBody<Vec<Scalar>>,
    // deterministic_noise: &Vec<Scalar>,
) where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    KeyCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    if row_index < last_row_index {
        // Not the last row
        let sk_poly_list = glwe_secret_key.as_polynomial_list();
        let sk_poly = sk_poly_list.get(row_index);

        // Copy the key polynomial to the output body, to avoid allocating a temporary buffer
        let mut body = row_as_glwe.get_mut_body();
        body.as_mut().copy_from_slice(sk_poly.as_ref());

        let ciphertext_modulus = body.ciphertext_modulus();

        match ciphertext_modulus.kind() {
            CiphertextModulusKind::Other => slice_wrapping_scalar_mul_assign_custom_mod(
                body.as_mut(),
                factor,
                ciphertext_modulus.get_custom_modulus().cast_into(),
            ),
            CiphertextModulusKind::Native | CiphertextModulusKind::NonNativePowerOfTwo => {
                slice_wrapping_scalar_mul_assign(body.as_mut(), factor)
            }
        }
    } else {
        // The last row needs a slightly different treatment
        let mut body = row_as_glwe.get_mut_body();
        let ciphertext_modulus = body.ciphertext_modulus();

        body.as_mut().fill(Scalar::ZERO);
        let encoded = match ciphertext_modulus.kind() {
            CiphertextModulusKind::Other => {
                factor.wrapping_neg_custom_mod(ciphertext_modulus.get_custom_modulus().cast_into())
            }
            CiphertextModulusKind::Native | CiphertextModulusKind::NonNativePowerOfTwo => {
                factor.wrapping_neg()
            }
        };
        body.as_mut()[0] = encoded;
    }
    encrypt_seeded_glwe_ciphertext_assign_with_existing_generator_deterministic(
        glwe_secret_key,
        row_as_glwe,
        noise_distribution,
        generator,
        deterministic_mask,
        deterministic_noise,
    );
}

pub fn encrypt_seeded_glwe_ciphertext_assign_with_existing_generator_deterministic<
    Scalar,
    NoiseDistribution,
    KeyCont,
    OutputCont,
    Gen,
>(
    glwe_secret_key: &GlweSecretKey<KeyCont>,
    output: &mut SeededGlweCiphertext<OutputCont>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
    deterministic_mask: &GlweMask<Vec<Scalar>>,
    deterministic_noise: &GlweBody<Vec<Scalar>>,
    // deterministic_noise: &Vec<Scalar>,
) where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    KeyCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert!(
        output.glwe_size().to_glwe_dimension() == glwe_secret_key.glwe_dimension(),
        "Mismatch between GlweDimension of output ciphertext and input secret key. \
        Got {:?} in output, and {:?} in secret key.",
        output.glwe_size().to_glwe_dimension(),
        glwe_secret_key.glwe_dimension()
    );
    assert!(
        output.polynomial_size() == glwe_secret_key.polynomial_size(),
        "Mismatch between PolynomialSize of output ciphertext and input secret key. \
        Got {:?} in output, and {:?} in secret key.",
        output.polynomial_size(),
        glwe_secret_key.polynomial_size()
    );

    let mut mask = GlweMask::from_container(
        vec![
            Scalar::ZERO;
            glwe_ciphertext_mask_size(
                output.glwe_size().to_glwe_dimension(),
                output.polynomial_size()
            )
        ],
        output.polynomial_size(),
        output.ciphertext_modulus(),
    );
    let mut body = output.get_mut_body();

    fill_glwe_mask_and_body_for_encryption_assign_deterministic(
        glwe_secret_key,
        &mut mask,
        &mut body,
        noise_distribution,
        generator,
        deterministic_mask,
        deterministic_noise,
    );
}

pub fn fill_glwe_mask_and_body_for_encryption_assign_deterministic<
    Scalar,
    NoiseDistribution,
    KeyCont,
    BodyCont,
    MaskCont,
    Gen,
>(
    glwe_secret_key: &GlweSecretKey<KeyCont>,
    output_mask: &mut GlweMask<MaskCont>,
    output_body: &mut GlweBody<BodyCont>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
    deterministic_mask: &GlweMask<Vec<Scalar>>,
    // deterministic_noise: &Vec<Scalar>,
    deterministic_noise: &GlweBody<Vec<Scalar>>,
) where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    KeyCont: Container<Element = Scalar>,
    BodyCont: ContainerMut<Element = Scalar>,
    MaskCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    let ciphertext_modulus = output_body.ciphertext_modulus();

    if !ciphertext_modulus.is_compatible_with_native_modulus() {
        println!("NOT IMPLEMENTED: ciphertext_modulus NOT compatible with native modulus case");
    }
    fill_glwe_mask_and_body_for_encryption_assign_native_mod_compatible_deterministic(
        glwe_secret_key,
        output_mask,
        output_body,
        noise_distribution,
        generator,
        deterministic_mask,
        deterministic_noise,
    )
}

pub fn fill_glwe_mask_and_body_for_encryption_assign_native_mod_compatible_deterministic<
    Scalar,
    NoiseDistribution,
    KeyCont,
    BodyCont,
    MaskCont,
    Gen,
>(
    glwe_secret_key: &GlweSecretKey<KeyCont>,
    output_mask: &mut GlweMask<MaskCont>,
    output_body: &mut GlweBody<BodyCont>,
    _noise_distribution: NoiseDistribution,
    _generator: &mut EncryptionRandomGenerator<Gen>,
    deterministic_mask: &GlweMask<Vec<Scalar>>,
    // deterministic_noise: &Vec<Scalar>,
    deterministic_noise: &GlweBody<Vec<Scalar>>,
) where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    KeyCont: Container<Element = Scalar>,
    BodyCont: ContainerMut<Element = Scalar>,
    MaskCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert_eq!(
        output_mask.ciphertext_modulus(),
        output_body.ciphertext_modulus(),
        "Mismatched moduli between output_mask ({:?}) and output_body ({:?})",
        output_mask.ciphertext_modulus(),
        output_body.ciphertext_modulus()
    );

    let ciphertext_modulus = output_body.ciphertext_modulus();

    assert!(ciphertext_modulus.is_compatible_with_native_modulus());

    // output_mask = deterministic_mask
    output_mask.as_mut().copy_from_slice(deterministic_mask.as_ref());    
    // output_body = msg + deterministic_noise
    if !ciphertext_modulus.is_native_modulus() {
        let torus_scaling = ciphertext_modulus.get_power_of_two_scaling_to_native_torus();
        // slice_wrapping_scalar_mul_assign(output_mask.as_mut(), torus_scaling);
        slice_wrapping_scalar_mul_assign(output_body.as_mut(), torus_scaling);
    }
    slice_wrapping_add_assign(output_body.as_mut(), deterministic_noise.as_ref());
    // slice_wrapping_add_assign(output_body.as_mut(), deterministic_noise);
    // output_body.as_mut().copy_from_slice(deterministic_noise);    

    // output_body =  deterministic_noise + output_mask * glwe_secret_key
    // let noise = output_body.as_ref().to_vec();
    // println!("deterministic_noise: {:?}", deterministic_noise);
    // println!("deterministic_mask: {:?}", deterministic_mask);
    // println!("noise: {:?}", noise);
    // println!("output_mask: {:?}", output_mask.as_polynomial_list());
    // println!("glwe_secret_key: {:?}", glwe_secret_key.as_polynomial_list());
    polynomial_wrapping_add_multisum_assign(
        &mut output_body.as_mut_polynomial(),
        &output_mask.as_polynomial_list(),
        &glwe_secret_key.as_polynomial_list(),
    );
    // println!("output_body: {:?}", output_body.as_polynomial());
}

pub fn par_encrypt_constant_seeded_ggsw_ciphertext_ret_mask_and_noise<
    Scalar,
    NoiseDistribution,
    KeyCont,
    OutputCont,
    NoiseSeeder,
>(
    glwe_secret_key: &GlweSecretKey<KeyCont>,
    output: &mut SeededGgswCiphertext<OutputCont>,
    cleartext: Cleartext<Scalar>,
    noise_distribution: NoiseDistribution,
    noise_seeder: &mut NoiseSeeder,
// ) 
// ) -> (Vec<GlweMask<Vec<Scalar>>>, Vec<Vec<Scalar>>)
// ) -> (Vec<Vec<GlweMask<Vec<Scalar>>>>, Vec<Vec<Vec<Scalar>>>)
) -> (Vec<Vec<GlweMask<Vec<Scalar>>>>, Vec<Vec<GlweBody<Vec<Scalar>>>>)
where
    Scalar: Encryptable<Uniform, NoiseDistribution> + Sync + Send,
    NoiseDistribution: Distribution + Sync,
    KeyCont: Container<Element = Scalar> + Sync,
    OutputCont: ContainerMut<Element = Scalar>,
    // Maybe Sized allows to pass Box<dyn Seeder>.
    NoiseSeeder: Seeder + ?Sized,
{
    assert!(
        output.polynomial_size() == glwe_secret_key.polynomial_size(),
        "Mismatch between polynomial sizes of output ciphertexts and input secret key. \
        Got {:?} in output, and {:?} in secret key.",
        output.polynomial_size(),
        glwe_secret_key.polynomial_size()
    );

    assert!(
        output.glwe_size().to_glwe_dimension() == glwe_secret_key.glwe_dimension(),
        "Mismatch between GlweDimension of output ciphertexts and input secret key. \
        Got {:?} in output, and {:?} in secret key.",
        output.glwe_size().to_glwe_dimension(),
        glwe_secret_key.glwe_dimension()
    );

    let mut generator = EncryptionRandomGenerator::<DefaultRandomGenerator>::new(
        output.compression_seed().seed,
        noise_seeder,
    );

    par_encrypt_constant_seeded_ggsw_ciphertext_with_existing_generator_ret_mask_and_noise(
        glwe_secret_key,
        output,
        cleartext,
        noise_distribution,
        &mut generator,
    )
}

pub fn par_encrypt_constant_seeded_ggsw_ciphertext_with_existing_generator_update_mask_and_noise<
    Scalar,
    NoiseDistribution,
    KeyCont,
    OutputCont,
    Gen,
>(
    glwe_secret_key: &GlweSecretKey<KeyCont>,
    output: &mut SeededGgswCiphertext<OutputCont>,
    cleartext: Cleartext<Scalar>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
    mask_vector: &mut Vec<Vec<GlweMask<Vec<Scalar>>>>,
    // noise_vector: &mut  Vec<Vec<Vec<Scalar>>>,
    noise_vector: &mut  Vec<Vec<GlweBody<Vec<Scalar>>>>,
) 
// ) -> (Vec<GlweMask<Vec<Scalar>>>, Vec<Vec<Scalar>>)
where
    Scalar: Encryptable<Uniform, NoiseDistribution> + Sync + Send,
    NoiseDistribution: Distribution + Sync,
    KeyCont: Container<Element = Scalar> + Sync,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ParallelByteRandomGenerator,
{
    (*mask_vector, *noise_vector) = par_encrypt_constant_seeded_ggsw_ciphertext_with_existing_generator_ret_mask_and_noise(
                                        glwe_secret_key,
                                        output,
                                        cleartext,
                                        noise_distribution,
                                        generator,
                                    );
}

pub fn par_encrypt_constant_seeded_ggsw_ciphertext_with_existing_generator_ret_mask_and_noise<
    Scalar,
    NoiseDistribution,
    KeyCont,
    OutputCont,
    Gen,
>(
    glwe_secret_key: &GlweSecretKey<KeyCont>,
    output: &mut SeededGgswCiphertext<OutputCont>,
    cleartext: Cleartext<Scalar>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
// ) 
// ) -> (Vec<GlweMask<Vec<Scalar>>>, Vec<Vec<Scalar>>)
// ) -> (Vec<Vec<GlweMask<Vec<Scalar>>>>, Vec<Vec<Vec<Scalar>>>)
) -> (Vec<Vec<GlweMask<Vec<Scalar>>>>, Vec<Vec<GlweBody<Vec<Scalar>>>>)
where
    Scalar: Encryptable<Uniform, NoiseDistribution> + Sync + Send,
    NoiseDistribution: Distribution + Sync,
    KeyCont: Container<Element = Scalar> + Sync,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ParallelByteRandomGenerator,
{
    // Generators used to have same sequential and parallel key generation
    let gen_iter = generator
        .par_try_fork_from_config(output.encryption_fork_config(Uniform, noise_distribution))
        .expect("Failed to split generator into ggsw levels");

    let decomp_base_log = output.decomposition_base_log();
    let decomp_level_count = output.decomposition_level_count();
    let polynomial_size = output.polynomial_size();
    let glwe_size = output.glwe_size();
    let ciphertext_modulus = output.ciphertext_modulus();

    // Ensure 3D vectors for masks and noise
    // let mut noise_vector = 
    //     vec![
    //         vec![
    //             vec![Scalar::ZERO;
    //                 polynomial_size.0];
    //             glwe_size.0
    //         ]; 
    //     decomp_level_count.0
    // ];
    let mut noise_vector = 
        vec![
            vec![
                GlweBody::from_container(
                    vec![
                        Scalar::ZERO;
                        polynomial_size.0
                    ],
                    // polynomial_size,
                    ciphertext_modulus,
                );
                glwe_size.0
            ];
        decomp_level_count.0
    ];
    let mut mask_vector = 
        vec![
            vec![
                GlweMask::from_container(
                    vec![
                        Scalar::ZERO;
                        glwe_ciphertext_mask_size(glwe_size.to_glwe_dimension(), polynomial_size)
                    ],
                    polynomial_size,
                    ciphertext_modulus,
                );
                glwe_size.0
            ];
        decomp_level_count.0
    ];

    // Iterate over `output` with proper parallelization
    output
        .par_iter_mut()
        .zip(gen_iter)
        .enumerate()
        .zip(mask_vector.par_iter_mut())
        .zip(noise_vector.par_iter_mut())
        .for_each(|(((output_index, (mut level_matrix, mut generator)), mask_chunk), noise_chunk)| {

            let decomp_level = DecompositionLevel(decomp_level_count.0 - output_index);
            let factor = ggsw_encryption_multiplicative_factor(
                ciphertext_modulus,
                decomp_level,
                decomp_base_log,
                cleartext,
            );

            // Split generator for each GLWE level
            let gen_iter = generator
                .par_try_fork_from_config(
                    level_matrix.encryption_fork_config(Uniform, noise_distribution),
                )
                .expect("Failed to split generator into glwe");

            let last_row_index = level_matrix.glwe_size().0 - 1;

            // // Get 2D slices for `mask_vector` and `noise_vector`
            // let mask_chunk = &mut mask_vector[output_index];
            // let noise_chunk = &mut noise_vector[output_index];

            level_matrix
                .as_mut_seeded_glwe_list()
                .par_iter_mut()
                .enumerate()
                .zip(gen_iter)
                .zip(mask_chunk.par_iter_mut())
                .zip(noise_chunk.par_iter_mut())
                .for_each(|((((row_index, mut row_as_glwe), mut generator), mut mask_entry), mut noise_entry)| {
                    // let mask_entry = &mut mask_chunk[row_index];
                    // let noise_entry = &mut noise_chunk[row_index];

                    encrypt_constant_seeded_ggsw_level_matrix_row_update_mask_and_noise(
                        glwe_secret_key,
                        (row_index, last_row_index),
                        factor,
                        &mut row_as_glwe,
                        noise_distribution,
                        &mut generator,
                        &mut mask_entry,
                        &mut noise_entry,
                    );
                });
        });

    (mask_vector, noise_vector)
}

pub fn par_encrypt_constant_seeded_ggsw_ciphertext_deterministic<
    Scalar,
    NoiseDistribution,
    KeyCont,
    OutputCont,
    NoiseSeeder,
>(
    glwe_secret_key: &GlweSecretKey<KeyCont>,
    output: &mut SeededGgswCiphertext<OutputCont>,
    cleartext: Cleartext<Scalar>,
    noise_distribution: NoiseDistribution,
    noise_seeder: &mut NoiseSeeder,
    // mask_vector: &Vec<GlweMask<Vec<Scalar>>>,
    // noise_vector: &Vec<Vec<Scalar>>,
    mask_vector: &Vec<Vec<GlweMask<Vec<Scalar>>>>,
    // noise_vector: &Vec<Vec<Vec<Scalar>>>,
    noise_vector: &Vec<Vec<GlweBody<Vec<Scalar>>>>,
) where
    Scalar: Encryptable<Uniform, NoiseDistribution> + Sync + Send,
    NoiseDistribution: Distribution + Sync,
    KeyCont: Container<Element = Scalar> + Sync,
    OutputCont: ContainerMut<Element = Scalar>,
    // Maybe Sized allows to pass Box<dyn Seeder>.
    NoiseSeeder: Seeder + ?Sized,
{
    assert!(
        output.polynomial_size() == glwe_secret_key.polynomial_size(),
        "Mismatch between polynomial sizes of output ciphertexts and input secret key. \
        Got {:?} in output, and {:?} in secret key.",
        output.polynomial_size(),
        glwe_secret_key.polynomial_size()
    );

    assert!(
        output.glwe_size().to_glwe_dimension() == glwe_secret_key.glwe_dimension(),
        "Mismatch between GlweDimension of output ciphertexts and input secret key. \
        Got {:?} in output, and {:?} in secret key.",
        output.glwe_size().to_glwe_dimension(),
        glwe_secret_key.glwe_dimension()
    );

    let mut generator = EncryptionRandomGenerator::<DefaultRandomGenerator>::new(
        output.compression_seed().seed,
        noise_seeder,
    );

    par_encrypt_constant_seeded_ggsw_ciphertext_with_existing_generator_deterministic(
        glwe_secret_key,
        output,
        cleartext,
        noise_distribution,
        &mut generator,
        mask_vector,
        noise_vector,
    );
}

pub fn par_encrypt_constant_seeded_ggsw_ciphertext_with_existing_generator_deterministic<
    Scalar,
    NoiseDistribution,
    KeyCont,
    OutputCont,
    Gen,
>(
    glwe_secret_key: &GlweSecretKey<KeyCont>,
    output: &mut SeededGgswCiphertext<OutputCont>,
    cleartext: Cleartext<Scalar>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
    // mask_vector: &Vec<GlweMask<Vec<Scalar>>>,
    // noise_vector: &Vec<Vec<Scalar>>,
    mask_vector: &Vec<Vec<GlweMask<Vec<Scalar>>>>,
    // noise_vector: &Vec<Vec<Vec<Scalar>>>,
    noise_vector: &Vec<Vec<GlweBody<Vec<Scalar>>>>,
) where
    Scalar: Encryptable<Uniform, NoiseDistribution> + Sync + Send,
    NoiseDistribution: Distribution + Sync,
    KeyCont: Container<Element = Scalar> + Sync,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ParallelByteRandomGenerator,
{
    // Generators used to have same sequential and parallel key generation
    let gen_iter = generator
        .par_try_fork_from_config(output.encryption_fork_config(Uniform, noise_distribution))
        .expect("Failed to split generator into ggsw levels");

    let decomp_base_log = output.decomposition_base_log();
    let decomp_level_count = output.decomposition_level_count();
    let ciphertext_modulus = output.ciphertext_modulus();

    output.par_iter_mut().zip(gen_iter).enumerate().for_each(
        |(output_index, (mut level_matrix, mut generator))| {
            let decomp_level = DecompositionLevel(decomp_level_count.0 - output_index);
            let factor = ggsw_encryption_multiplicative_factor(
                ciphertext_modulus,
                decomp_level,
                decomp_base_log,
                cleartext,
            );

            // We iterate over the rows of the level matrix, the last row needs special treatment
            let gen_iter = generator
                .par_try_fork_from_config(
                    level_matrix.encryption_fork_config(Uniform, noise_distribution),
                )
                .expect("Failed to split generator into glwe");

            let last_row_index = level_matrix.glwe_size().0 - 1;

            level_matrix
                .as_mut_seeded_glwe_list()
                .par_iter_mut()
                .enumerate()
                .zip(gen_iter)
                .for_each(|((row_index, mut row_as_glwe), mut generator)| {
                    encrypt_constant_seeded_ggsw_level_matrix_row_deterministic(
                    // encrypt_constant_seeded_ggsw_level_matrix_row(
                        glwe_secret_key,
                        (row_index, last_row_index),
                        factor,
                        &mut row_as_glwe,
                        noise_distribution,
                        &mut generator,
                        // &mask_vector[(last_row_index+1) * output_index + row_index],
                        // &noise_vector[(last_row_index+1) * output_index + row_index],
                        &mask_vector[output_index][row_index],
                        &noise_vector[output_index][row_index],
                    );
                });
        },
    );
}

pub fn par_allocate_and_generate_new_seeded_lwe_bootstrap_key_ret_mask_and_noise<
    Scalar,
    NoiseDistribution,
    InputKeyCont,
    OutputKeyCont,
    NoiseSeeder,
>(
    input_lwe_secret_key: &LweSecretKey<InputKeyCont>,
    output_glwe_secret_key: &GlweSecretKey<OutputKeyCont>,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    noise_distribution: NoiseDistribution,
    ciphertext_modulus: CiphertextModulus<Scalar>,
    noise_seeder: &mut NoiseSeeder,
// ) -> (SeededLweBootstrapKeyOwned<Scalar>, Vec<Vec<Vec<GlweMask<Vec<Scalar>>>>>, Vec<Vec<Vec<Vec<Scalar>>>>)
) -> (SeededLweBootstrapKeyOwned<Scalar>, Vec<Vec<Vec<GlweMask<Vec<Scalar>>>>>, Vec<Vec<Vec<GlweBody<Vec<Scalar>>>>>)
where
    Scalar: Encryptable<Uniform, NoiseDistribution> + Sync + Send,
    NoiseDistribution: Distribution + Sync,
    InputKeyCont: Container<Element = Scalar>,
    OutputKeyCont: Container<Element = Scalar> + Sync,
    // Maybe Sized allows to pass Box<dyn Seeder>.
    NoiseSeeder: Seeder + ?Sized,
{
    let mut bsk = SeededLweBootstrapKeyOwned::new(
        Scalar::ZERO,
        output_glwe_secret_key.glwe_dimension().to_glwe_size(),
        output_glwe_secret_key.polynomial_size(),
        decomp_base_log,
        decomp_level_count,
        input_lwe_secret_key.lwe_dimension(),
        noise_seeder.seed().into(),
        ciphertext_modulus,
    );

    let (mask_vector, noise_vector) = par_generate_seeded_lwe_bootstrap_key_ret_mask_and_noise(
        input_lwe_secret_key,
        output_glwe_secret_key,
        &mut bsk,
        noise_distribution,
        noise_seeder,
    );

    (bsk, mask_vector, noise_vector)
}

pub fn par_generate_seeded_lwe_bootstrap_key_ret_mask_and_noise<
    Scalar,
    NoiseDistribution,
    InputKeyCont,
    OutputKeyCont,
    OutputCont,
    NoiseSeeder,
>(
    input_lwe_secret_key: &LweSecretKey<InputKeyCont>,
    output_glwe_secret_key: &GlweSecretKey<OutputKeyCont>,
    output: &mut SeededLweBootstrapKey<OutputCont>,
    noise_distribution: NoiseDistribution,
    noise_seeder: &mut NoiseSeeder,
// ) -> (Vec<Vec<Vec<GlweMask<Vec<Scalar>>>>>, Vec<Vec<Vec<Vec<Scalar>>>>)
) -> (Vec<Vec<Vec<GlweMask<Vec<Scalar>>>>>, Vec<Vec<Vec<GlweBody<Vec<Scalar>>>>>)
where
    Scalar: Encryptable<Uniform, NoiseDistribution> + Sync + Send,
    NoiseDistribution: Distribution + Sync,
    InputKeyCont: Container<Element = Scalar>,
    OutputKeyCont: Container<Element = Scalar> + Sync,
    OutputCont: ContainerMut<Element = Scalar>,
    // Maybe Sized allows to pass Box<dyn Seeder>.
    NoiseSeeder: Seeder + ?Sized,
{
    assert!(
        output.input_lwe_dimension() == input_lwe_secret_key.lwe_dimension(),
        "Mismatched LweDimension between input LWE secret key and LWE bootstrap key. \
        Input LWE secret key LweDimension: {:?}, LWE bootstrap key input LweDimension {:?}.",
        input_lwe_secret_key.lwe_dimension(),
        output.input_lwe_dimension()
    );

    assert!(
        output.glwe_size() == output_glwe_secret_key.glwe_dimension().to_glwe_size(),
        "Mismatched GlweSize between output GLWE secret key and LWE bootstrap key. \
        Output GLWE secret key GlweSize: {:?}, LWE bootstrap key GlweSize {:?}.",
        output_glwe_secret_key.glwe_dimension().to_glwe_size(),
        output.glwe_size()
    );

    assert!(
        output.polynomial_size() == output_glwe_secret_key.polynomial_size(),
        "Mismatched PolynomialSize between output GLWE secret key and LWE bootstrap key. \
        Output GLWE secret key PolynomialSize: {:?}, LWE bootstrap key PolynomialSize {:?}.",
        output_glwe_secret_key.polynomial_size(),
        output.polynomial_size()
    );

    let mut generator = EncryptionRandomGenerator::<DefaultRandomGenerator>::new(
        output.compression_seed().seed,
        noise_seeder,
    );

    let gen_iter = generator
        .par_try_fork_from_config(output.encryption_fork_config(Uniform, noise_distribution))
        .unwrap();

    // Ensure 4D vectors for masks and noise
    let polynomial_size = output.polynomial_size();
    let glwe_size = output.glwe_size();
    let decomp_level_count = output.decomposition_level_count();
    let input_lwe_dimension = output.input_lwe_dimension();
    let ciphertext_modulus = output.ciphertext_modulus();
    // let mut noise_vector = 
    //     vec![
    //         vec![
    //             vec![
    //                 vec![Scalar::ZERO;
    //                     polynomial_size.0];
    //                 glwe_size.0
    //             ]; 
    //         decomp_level_count.0
    //         ];
    //     input_lwe_dimension.0
    // ];
    let mut noise_vector = 
        vec![
            vec![
                vec![
                    GlweBody::from_container(
                        vec![
                            Scalar::ZERO;
                            polynomial_size.0
                        ],
                        // polynomial_size,
                        ciphertext_modulus,
                    );
                    glwe_size.0
                ];
            decomp_level_count.0
            ];
        input_lwe_dimension.0
    ];
    let mut mask_vector = 
        vec![
            vec![
                vec![
                    GlweMask::from_container(
                        vec![
                            Scalar::ZERO;
                            glwe_ciphertext_mask_size(glwe_size.to_glwe_dimension(), polynomial_size)
                        ],
                        polynomial_size,
                        ciphertext_modulus,
                    );
                    glwe_size.0
                ];
            decomp_level_count.0
            ];
        input_lwe_dimension.0
    ];

    output
        .par_iter_mut()
        .zip(input_lwe_secret_key.as_ref().par_iter())
        .zip(gen_iter)
        .zip(mask_vector.par_iter_mut())
        .zip(noise_vector.par_iter_mut())
        .for_each(|((((mut ggsw, &input_key_element), mut generator), mut mask_chunk), mut noise_chunk)| {
            par_encrypt_constant_seeded_ggsw_ciphertext_with_existing_generator_update_mask_and_noise(
                output_glwe_secret_key,
                &mut ggsw,
                Cleartext(input_key_element),
                noise_distribution,
                &mut generator,
                &mut mask_chunk,
                &mut noise_chunk,
            );
        });
    (mask_vector, noise_vector)
}


pub fn allocate_and_encrypt_new_lwe_ciphertext_ret_noise<Scalar, NoiseDistribution, KeyCont, Gen>(
    lwe_secret_key: &LweSecretKey<KeyCont>,
    encoded: Plaintext<Scalar>,
    noise_distribution: NoiseDistribution,
    ciphertext_modulus: CiphertextModulus<Scalar>,
    generator: &mut EncryptionRandomGenerator<Gen>,
// ) -> (LweCiphertextOwned<Scalar>, Scalar)
) -> (LweCiphertextOwned<Scalar>, LweBody<Scalar>)
where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    KeyCont: Container<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    let mut new_ct = LweCiphertextOwned::new(
        Scalar::ZERO,
        lwe_secret_key.lwe_dimension().to_lwe_size(),
        ciphertext_modulus,
    );

    let noise = encrypt_lwe_ciphertext_ret_noise(
        lwe_secret_key,
        &mut new_ct,
        encoded,
        noise_distribution,
        generator,
    );

    (new_ct, noise)
}

pub fn blind_rotate_assign_ret_noise<
    InputScalar, 
    OutputScalar, 
    InputCont, 
    OutputCont, 
    KeyCont, 
    Scalar, 
    // NoiseDistribution,
>(
    input: &LweCiphertext<InputCont>,
    lut: &mut GlweCiphertext<OutputCont>,
    fourier_bsk: &FourierLweBootstrapKey<KeyCont>,
    // input_mask: &LweMask<InputCont>,
    input_mask: &LweMask<&[Scalar]>,
    input_noise: &LweBody<Scalar>,
    // lut_mask: &GlweMask<OutputCont>,
    // lut_noise: &GlweBody<OutputCont>,
    bsk_mask_vector: Vec<Vec<Vec<GlweMask<Vec<Scalar>>>>>,
    bsk_noise_vector: Vec<Vec<Vec<GlweBody<Vec<Scalar>>>>>,
// )
) -> GlweBody<Vec<Scalar>>
// ) -> GlweBody<OutputCont>
where
    // CastInto required for PBS modulus switch which returns a usize
    InputScalar: UnsignedTorus + CastInto<usize>,
    OutputScalar: UnsignedTorus,
    // InputCont: Container<Element = InputScalar> + UnsignedInteger,
    InputCont: Container<Element = InputScalar>,
    OutputCont: ContainerMut<Element = OutputScalar>,
    KeyCont: Container<Element = c64>,
    // Scalar: Encryptable<Uniform, NoiseDistribution> + Sync + Send + UnsignedTorus,
    Scalar: UnsignedTorus,
    // NoiseDistribution: Distribution,
{
    assert!(
        input.ciphertext_modulus().is_power_of_two(),
        "This operation requires the input to have a power of two modulus."
    );
    assert!(
        lut.ciphertext_modulus().is_power_of_two(),
        "This operation requires the lut to have a power of two modulus."
    );

    let mut buffers = ComputationBuffers::new();

    let fft = Fft::new(fourier_bsk.polynomial_size());
    let fft = fft.as_view();

    buffers.resize(
        blind_rotate_assign_mem_optimized_requirement::<OutputScalar>(
            fourier_bsk.glwe_size(),
            fourier_bsk.polynomial_size(),
            fft,
        )
        .unwrap()
        .unaligned_bytes_required(),
    );

    let stack = buffers.stack();

    blind_rotate_assign_mem_optimized_ret_noise(input, lut, fourier_bsk, fft, stack, 
        // input_mask, input_noise, lut_mask, lut_noise, bsk_mask_vector, bsk_noise_vector)
        input_mask, input_noise, bsk_mask_vector, bsk_noise_vector)
}

pub fn blind_rotate_assign_mem_optimized_ret_noise<
    InputScalar,
    OutputScalar,
    InputCont,
    OutputCont,
    KeyCont,
    Scalar, 
    // NoiseDistribution,
>(
    input: &LweCiphertext<InputCont>,
    lut: &mut GlweCiphertext<OutputCont>,
    fourier_bsk: &FourierLweBootstrapKey<KeyCont>,
    fft: FftView<'_>,
    stack: &mut PodStack,
    // input_mask: &LweMask<InputCont>,
    input_mask: &LweMask<&[Scalar]>,
    input_noise: &LweBody<Scalar>,
    // lut_mask: &GlweMask<OutputCont>,
    // lut_noise: &GlweBody<OutputCont>,
    bsk_mask_vector: Vec<Vec<Vec<GlweMask<Vec<Scalar>>>>>,
    bsk_noise_vector: Vec<Vec<Vec<GlweBody<Vec<Scalar>>>>>,
// ) 
// ) -> GlweBody<OutputCont>
) -> GlweBody<Vec<Scalar>>
where
    // CastInto required for PBS modulus switch which returns a usize
    InputScalar: UnsignedTorus + CastInto<usize>,
    OutputScalar: UnsignedTorus,
    // InputCont: Container<Element = InputScalar> + UnsignedInteger,
    InputCont: Container<Element = InputScalar>,
    OutputCont: ContainerMut<Element = OutputScalar>,
    KeyCont: Container<Element = c64>,
    Scalar: UnsignedTorus,
    // Scalar: Encryptable<Uniform, NoiseDistribution> + Sync + Send,
    // NoiseDistribution: Distribution,
{
    assert!(
        input.ciphertext_modulus().is_power_of_two(),
        "This operation requires the input to have a power of two modulus."
    );
    assert!(
        lut.ciphertext_modulus().is_power_of_two(),
        "This operation requires the lut to have a power of two modulus."
    );
    assert_eq!(
        input.lwe_size(),
        fourier_bsk.input_lwe_dimension().to_lwe_size()
    );
    assert_eq!(lut.glwe_size(), fourier_bsk.glwe_size());
    assert_eq!(lut.polynomial_size(), fourier_bsk.polynomial_size());

    // Blind rotate assign manages the rounding to go back to the proper torus if the ciphertext
    // modulus is not the native one
    fourier_bsk
        .as_view()
        .blind_rotate_assign_ret_noise(lut.as_mut_view(), input.as_view(), fft, stack,
            // input_mask, input_noise, lut_mask, lut_noise, bsk_mask_vector, bsk_noise_vector)
            input_mask, input_noise, bsk_mask_vector, bsk_noise_vector)
}

pub fn allocate_and_generate_new_lwe_keyswitch_key_ret_mask_and_noise<
    Scalar,
    NoiseDistribution,
    InputKeyCont,
    OutputKeyCont,
    Gen,
>(
    input_lwe_sk: &LweSecretKey<InputKeyCont>,
    output_lwe_sk: &LweSecretKey<OutputKeyCont>,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    noise_distribution: NoiseDistribution,
    ciphertext_modulus: CiphertextModulus<Scalar>,
    generator: &mut EncryptionRandomGenerator<Gen>,
// ) -> (LweKeyswitchKeyOwned<Scalar>, Vec<LweMask<Vec<Scalar>>>, Vec<LweBody<Scalar>>)
) -> (LweKeyswitchKeyOwned<Scalar>, Vec<Vec<LweMask<Vec<Scalar>>>>, Vec<Vec<LweBody<Scalar>>>, Vec<PlaintextListOwned<Scalar>>)
where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    InputKeyCont: Container<Element = Scalar>,
    OutputKeyCont: Container<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    let mut new_lwe_keyswitch_key = LweKeyswitchKeyOwned::new(
        Scalar::ZERO,
        decomp_base_log,
        decomp_level_count,
        input_lwe_sk.lwe_dimension(),
        output_lwe_sk.lwe_dimension(),
        ciphertext_modulus,
    );

    let (ksk_mask_vector, ksk_noise_vector, plaintexts_vector) = generate_lwe_keyswitch_key_ret_mask_and_noise(
        input_lwe_sk,
        output_lwe_sk,
        &mut new_lwe_keyswitch_key,
        noise_distribution,
        generator,
    );

    (new_lwe_keyswitch_key, ksk_mask_vector, ksk_noise_vector, plaintexts_vector)
}

pub fn generate_lwe_keyswitch_key_ret_mask_and_noise<
    Scalar,
    NoiseDistribution,
    InputKeyCont,
    OutputKeyCont,
    KSKeyCont,
    Gen,
>(
    input_lwe_sk: &LweSecretKey<InputKeyCont>,
    output_lwe_sk: &LweSecretKey<OutputKeyCont>,
    lwe_keyswitch_key: &mut LweKeyswitchKey<KSKeyCont>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
// ) -> (Vec<LweMask<Vec<Scalar>>>, Vec<LweBody<Scalar>>)
) -> (Vec<Vec<LweMask<Vec<Scalar>>>>, Vec<Vec<LweBody<Scalar>>>, Vec<PlaintextListOwned<Scalar>>)
where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    InputKeyCont: Container<Element = Scalar>,
    OutputKeyCont: Container<Element = Scalar>,
    KSKeyCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    let ciphertext_modulus = lwe_keyswitch_key.ciphertext_modulus();

    if !ciphertext_modulus.is_compatible_with_native_modulus() {
        println!("NOT IMPLEMENTED: ciphertext_modulus NOT compatible with native modulus case");
    }
    generate_lwe_keyswitch_key_native_mod_compatible_ret_mask_and_noise(
        input_lwe_sk,
        output_lwe_sk,
        lwe_keyswitch_key,
        noise_distribution,
        generator,
    )
}

pub fn generate_lwe_keyswitch_key_native_mod_compatible_ret_mask_and_noise<
    Scalar,
    NoiseDistribution,
    InputKeyCont,
    OutputKeyCont,
    KSKeyCont,
    Gen,
>(
    input_lwe_sk: &LweSecretKey<InputKeyCont>,
    output_lwe_sk: &LweSecretKey<OutputKeyCont>,
    lwe_keyswitch_key: &mut LweKeyswitchKey<KSKeyCont>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
// ) 
) -> (Vec<Vec<LweMask<Vec<Scalar>>>>, Vec<Vec<LweBody<Scalar>>>, Vec<PlaintextListOwned<Scalar>>)
where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    InputKeyCont: Container<Element = Scalar>,
    OutputKeyCont: Container<Element = Scalar>,
    KSKeyCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert!(
        lwe_keyswitch_key.input_key_lwe_dimension() == input_lwe_sk.lwe_dimension(),
        "The destination LweKeyswitchKey input LweDimension is not equal \
    to the input LweSecretKey LweDimension. Destination: {:?}, input: {:?}",
        lwe_keyswitch_key.input_key_lwe_dimension(),
        input_lwe_sk.lwe_dimension()
    );
    assert!(
        lwe_keyswitch_key.output_key_lwe_dimension() == output_lwe_sk.lwe_dimension(),
        "The destination LweKeyswitchKey output LweDimension is not equal \
    to the output LweSecretKey LweDimension. Destination: {:?}, output: {:?}",
        lwe_keyswitch_key.output_key_lwe_dimension(),
        output_lwe_sk.lwe_dimension()
    );

    let decomp_base_log = lwe_keyswitch_key.decomposition_base_log();
    let decomp_level_count = lwe_keyswitch_key.decomposition_level_count();
    let ciphertext_modulus = lwe_keyswitch_key.ciphertext_modulus();
    assert!(ciphertext_modulus.is_compatible_with_native_modulus());

    // The plaintexts used to encrypt a key element will be stored in this buffer
    let mut decomposition_plaintexts_buffer_vector =
        vec![
            PlaintextListOwned::new(Scalar::ZERO, PlaintextCount(decomp_level_count.0));
            lwe_keyswitch_key.input_key_lwe_dimension().0
        ];

    let mut new_ciphertext_modulus = CiphertextModulus::<Scalar>::new_native();
    if !ciphertext_modulus.is_native_modulus() {
        new_ciphertext_modulus = CiphertextModulus::<Scalar>::new(ciphertext_modulus.get_custom_modulus());
    }
    let mut noise_vector = 
        vec![
            vec![
                LweBody::new(Scalar::ZERO, new_ciphertext_modulus);
                decomp_level_count.0
            ];
            lwe_keyswitch_key.input_key_lwe_dimension().0
        ];
    let mut mask_vector = 
        vec![
            vec![
                LweMask::from_container(
                    vec![
                        Scalar::ZERO; 
                        lwe_keyswitch_key.output_key_lwe_dimension().0
                    ], 
                    new_ciphertext_modulus);
                decomp_level_count.0
            ];
            lwe_keyswitch_key.input_key_lwe_dimension().0
        ];



    // Iterate over the input key elements and the destination lwe_keyswitch_key memory
    for ((((input_key_element, mut keyswitch_key_block), mask_chunk), noise_chunk), decomposition_plaintexts_buffer) in input_lwe_sk
        .as_ref()
        .iter()
        .zip(lwe_keyswitch_key.iter_mut())
        .zip(mask_vector.iter_mut())
        .zip(noise_vector.iter_mut())
        .zip(decomposition_plaintexts_buffer_vector.iter_mut())
    {
        // We fill the buffer with the powers of the key elements
        for (level, message) in (1..=decomp_level_count.0)
            .map(DecompositionLevel)
            .rev()
            .zip(decomposition_plaintexts_buffer.iter_mut())
        {
            // Here  we take the decomposition term from the native torus, bring it to the torus we
            // are working with by dividing by the scaling factor and the encryption will take care
            // of mapping that back to the native torus
            *message.0 = DecompositionTerm::new(level, decomp_base_log, *input_key_element)
                .to_recomposition_summand()
                .wrapping_div(ciphertext_modulus.get_power_of_two_scaling_to_native_torus());
        }

        // let (tmp_mask_chunk, tmp_noise_chunk) =encrypt_lwe_ciphertext_list_ret_mask_and_noise(
        (*mask_chunk, *noise_chunk) =encrypt_lwe_ciphertext_list_ret_mask_and_noise(
            output_lwe_sk,
            &mut keyswitch_key_block,
            &decomposition_plaintexts_buffer,
            noise_distribution,
            generator,
        );
        // mask_chunk.as_mut().copy_from_slice(tmp_mask_chunk.as_ref());
        // noise_chunk.as_mut().copy_from_slice(tmp_noise_chunk.as_ref());
    }

    (mask_vector, noise_vector, decomposition_plaintexts_buffer_vector)
}

pub fn keyswitch_lwe_ciphertext_ret_noise<Scalar, KSKCont, InputCont, OutputCont>(
    lwe_keyswitch_key: &LweKeyswitchKey<KSKCont>,
    input_lwe_ciphertext: &LweCiphertext<InputCont>,
    output_lwe_ciphertext: &mut LweCiphertext<OutputCont>,
    ksk_noise_vector: &Vec<Vec<LweBody<Scalar>>>,
    plaintextlist_vector: &Vec<PlaintextListOwned<Scalar>>,
// ) -> LweBody<Scalar>
) -> (LweBody<Scalar>, Plaintext<Scalar>)
where
    Scalar: UnsignedInteger,
    KSKCont: Container<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
{
    let ciphertext_modulus = lwe_keyswitch_key.ciphertext_modulus();

    if !ciphertext_modulus.is_compatible_with_native_modulus() {
        println!("NOT IMPLEMENTED: ciphertext_modulus NOT compatible with native modulus case");
    }
    keyswitch_lwe_ciphertext_native_mod_compatible_ret_noise(
        lwe_keyswitch_key,
        input_lwe_ciphertext,
        output_lwe_ciphertext,
        ksk_noise_vector,
        plaintextlist_vector,
    )
}

pub fn keyswitch_lwe_ciphertext_native_mod_compatible_ret_noise<Scalar, KSKCont, InputCont, OutputCont>(
    lwe_keyswitch_key: &LweKeyswitchKey<KSKCont>,
    input_lwe_ciphertext: &LweCiphertext<InputCont>,
    output_lwe_ciphertext: &mut LweCiphertext<OutputCont>,
    ksk_noise_vector: &Vec<Vec<LweBody<Scalar>>>,
    plaintextlist_vector: &Vec<PlaintextListOwned<Scalar>>,
// ) -> LweBody<Scalar>
) -> (LweBody<Scalar>, Plaintext<Scalar>)
where
    Scalar: UnsignedInteger,
    KSKCont: Container<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
{
    assert!(
        lwe_keyswitch_key.input_key_lwe_dimension()
            == input_lwe_ciphertext.lwe_size().to_lwe_dimension(),
        "Mismatched input LweDimension. \
        LweKeyswitchKey input LweDimension: {:?}, input LweCiphertext LweDimension {:?}.",
        lwe_keyswitch_key.input_key_lwe_dimension(),
        input_lwe_ciphertext.lwe_size().to_lwe_dimension(),
    );
    assert!(
        lwe_keyswitch_key.output_key_lwe_dimension()
            == output_lwe_ciphertext.lwe_size().to_lwe_dimension(),
        "Mismatched output LweDimension. \
        LweKeyswitchKey output LweDimension: {:?}, output LweCiphertext LweDimension {:?}.",
        lwe_keyswitch_key.output_key_lwe_dimension(),
        output_lwe_ciphertext.lwe_size().to_lwe_dimension(),
    );

    let output_ciphertext_modulus = output_lwe_ciphertext.ciphertext_modulus();

    assert_eq!(
        lwe_keyswitch_key.ciphertext_modulus(),
        output_ciphertext_modulus,
        "Mismatched CiphertextModulus. \
        LweKeyswitchKey CiphertextModulus: {:?}, output LweCiphertext CiphertextModulus {:?}.",
        lwe_keyswitch_key.ciphertext_modulus(),
        output_ciphertext_modulus
    );
    assert!(
        output_ciphertext_modulus.is_compatible_with_native_modulus(),
        "This operation currently only supports power of 2 moduli"
    );

    let input_ciphertext_modulus = input_lwe_ciphertext.ciphertext_modulus();

    assert!(
        input_ciphertext_modulus.is_compatible_with_native_modulus(),
        "This operation currently only supports power of 2 moduli"
    );

    // Clear the output ciphertext, as it will get updated gradually
    output_lwe_ciphertext.as_mut().fill(Scalar::ZERO);

    let mut new_ciphertext_modulus = CiphertextModulus::<Scalar>::new_native();
    if !output_ciphertext_modulus.is_native_modulus() {
        new_ciphertext_modulus = CiphertextModulus::<Scalar>::new(output_ciphertext_modulus.get_custom_modulus());
    }
    let mut output_lwe_ciphertext_noise = LweBody::new(Scalar::ZERO, new_ciphertext_modulus);
    let mut noisy_message = Scalar::ZERO;

    // Copy the input body to the output ciphertext
    *output_lwe_ciphertext.get_mut_body().data = *input_lwe_ciphertext.get_body().data;

    // If the moduli are not the same, we need to round the body in the output ciphertext
    if output_ciphertext_modulus != input_ciphertext_modulus
        && !output_ciphertext_modulus.is_native_modulus()
    {
        let modulus_bits = output_ciphertext_modulus.get_custom_modulus().ilog2() as usize;
        let output_decomposer = SignedDecomposer::new(
            DecompositionBaseLog(modulus_bits),
            DecompositionLevelCount(1),
        );

        *output_lwe_ciphertext.get_mut_body().data =
            output_decomposer.closest_representable(*output_lwe_ciphertext.get_mut_body().data);
    }
    // start computing noisy message
    noisy_message = *output_lwe_ciphertext.get_body().data;

    // We instantiate a decomposer
    let decomposer = SignedDecomposer::new(
        lwe_keyswitch_key.decomposition_base_log(),
        lwe_keyswitch_key.decomposition_level_count(),
    );

    for (((keyswitch_key_block, &input_mask_element), ksk_noise_chunk), plaintextlist) in lwe_keyswitch_key
        .iter()
        .zip(input_lwe_ciphertext.get_mask().as_ref())
        .zip(ksk_noise_vector.iter())
        .zip(plaintextlist_vector.iter())
    {
        let decomposition_iter = decomposer.decompose(input_mask_element);
        // Loop over the levels
        for (((level_key_ciphertext, decomposed), ksk_noise_entry), plaintext) in keyswitch_key_block.iter().zip(decomposition_iter).zip(ksk_noise_chunk.iter()).zip(plaintextlist.as_ref())
        {
            slice_wrapping_sub_scalar_mul_assign(
                output_lwe_ciphertext.as_mut(),
                level_key_ciphertext.as_ref(),
                decomposed.value(),
            );
            // compute noise
            let tmp_val = ksk_noise_entry.data;
            output_lwe_ciphertext_noise.data = output_lwe_ciphertext_noise.data.wrapping_sub(
                tmp_val.wrapping_mul(decomposed.value())
            );
            // compute noisy message
            let tmp_noisy_message = plaintext;
            noisy_message = noisy_message.wrapping_sub(
                tmp_noisy_message.wrapping_mul(decomposed.value())
            );
        }
    }
    (output_lwe_ciphertext_noise, Plaintext(noisy_message))
}

pub fn allocate_and_generate_new_lwe_keyswitch_key_deterministic<
    Scalar,
    NoiseDistribution,
    InputKeyCont,
    OutputKeyCont,
    Gen,
>(
    input_lwe_sk: &LweSecretKey<InputKeyCont>,
    output_lwe_sk: &LweSecretKey<OutputKeyCont>,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    noise_distribution: NoiseDistribution,
    ciphertext_modulus: CiphertextModulus<Scalar>,
    generator: &mut EncryptionRandomGenerator<Gen>,
    mask_vector: &Vec<Vec<LweMask<Vec<Scalar>>>>,
    noise_vector: &Vec<Vec<LweBody<Scalar>>>,
// ) -> (LweKeyswitchKeyOwned<Scalar>, Vec<LweMask<Vec<Scalar>>>, Vec<LweBody<Scalar>>)
) -> LweKeyswitchKeyOwned<Scalar>
where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    InputKeyCont: Container<Element = Scalar>,
    OutputKeyCont: Container<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    let mut new_lwe_keyswitch_key = LweKeyswitchKeyOwned::new(
        Scalar::ZERO,
        decomp_base_log,
        decomp_level_count,
        input_lwe_sk.lwe_dimension(),
        output_lwe_sk.lwe_dimension(),
        ciphertext_modulus,
    );

    generate_lwe_keyswitch_key_deterministic(
        input_lwe_sk,
        output_lwe_sk,
        &mut new_lwe_keyswitch_key,
        noise_distribution,
        generator,
        mask_vector,
        noise_vector,
    );

    new_lwe_keyswitch_key
}

pub fn generate_lwe_keyswitch_key_deterministic<
    Scalar,
    NoiseDistribution,
    InputKeyCont,
    OutputKeyCont,
    KSKeyCont,
    Gen,
>(
    input_lwe_sk: &LweSecretKey<InputKeyCont>,
    output_lwe_sk: &LweSecretKey<OutputKeyCont>,
    lwe_keyswitch_key: &mut LweKeyswitchKey<KSKeyCont>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
    mask_vector: &Vec<Vec<LweMask<Vec<Scalar>>>>,
    noise_vector: &Vec<Vec<LweBody<Scalar>>>,
// ) -> (Vec<LweMask<Vec<Scalar>>>, Vec<LweBody<Scalar>>)
) where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    InputKeyCont: Container<Element = Scalar>,
    OutputKeyCont: Container<Element = Scalar>,
    KSKeyCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    let ciphertext_modulus = lwe_keyswitch_key.ciphertext_modulus();

    if !ciphertext_modulus.is_compatible_with_native_modulus() {
        println!("NOT IMPLEMENTED: ciphertext_modulus NOT compatible with native modulus case");
    }
    generate_lwe_keyswitch_key_native_mod_compatible_deterministic(
        input_lwe_sk,
        output_lwe_sk,
        lwe_keyswitch_key,
        noise_distribution,
        generator,
        mask_vector,
        noise_vector,
    )
}

pub fn generate_lwe_keyswitch_key_native_mod_compatible_deterministic<
    Scalar,
    NoiseDistribution,
    InputKeyCont,
    OutputKeyCont,
    KSKeyCont,
    Gen,
>(
    input_lwe_sk: &LweSecretKey<InputKeyCont>,
    output_lwe_sk: &LweSecretKey<OutputKeyCont>,
    lwe_keyswitch_key: &mut LweKeyswitchKey<KSKeyCont>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
    mask_vector: &Vec<Vec<LweMask<Vec<Scalar>>>>,
    noise_vector: &Vec<Vec<LweBody<Scalar>>>,
) 
// ) -> (Vec<Vec<LweMask<Vec<Scalar>>>>, Vec<Vec<LweBody<Scalar>>>)
where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    InputKeyCont: Container<Element = Scalar>,
    OutputKeyCont: Container<Element = Scalar>,
    KSKeyCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert!(
        lwe_keyswitch_key.input_key_lwe_dimension() == input_lwe_sk.lwe_dimension(),
        "The destination LweKeyswitchKey input LweDimension is not equal \
    to the input LweSecretKey LweDimension. Destination: {:?}, input: {:?}",
        lwe_keyswitch_key.input_key_lwe_dimension(),
        input_lwe_sk.lwe_dimension()
    );
    assert!(
        lwe_keyswitch_key.output_key_lwe_dimension() == output_lwe_sk.lwe_dimension(),
        "The destination LweKeyswitchKey output LweDimension is not equal \
    to the output LweSecretKey LweDimension. Destination: {:?}, output: {:?}",
        lwe_keyswitch_key.output_key_lwe_dimension(),
        output_lwe_sk.lwe_dimension()
    );

    let decomp_base_log = lwe_keyswitch_key.decomposition_base_log();
    let decomp_level_count = lwe_keyswitch_key.decomposition_level_count();
    let ciphertext_modulus = lwe_keyswitch_key.ciphertext_modulus();
    assert!(ciphertext_modulus.is_compatible_with_native_modulus());

    // The plaintexts used to encrypt a key element will be stored in this buffer
    let mut decomposition_plaintexts_buffer =
        PlaintextListOwned::new(Scalar::ZERO, PlaintextCount(decomp_level_count.0));

    // let mut new_ciphertext_modulus = CiphertextModulus::<Scalar>::new_native();
    // if !ciphertext_modulus.is_native_modulus() {
    //     new_ciphertext_modulus = CiphertextModulus::<Scalar>::new(ciphertext_modulus.get_custom_modulus());
    // }
    // let mut noise_vector = 
    //     vec![
    //         vec![
    //             LweBody::new(Scalar::ZERO, new_ciphertext_modulus);
    //             decomp_level_count.0
    //         ];
    //         lwe_keyswitch_key.input_key_lwe_dimension().0
    //     ];
    // let mut mask_vector = 
    //     vec![
    //         vec![
    //             LweMask::from_container(
    //                 vec![
    //                     Scalar::ZERO; 
    //                     lwe_keyswitch_key.output_key_lwe_dimension().0
    //                 ], 
    //                 new_ciphertext_modulus);
    //             decomp_level_count.0
    //         ];
    //         lwe_keyswitch_key.input_key_lwe_dimension().0
    //     ];



    // Iterate over the input key elements and the destination lwe_keyswitch_key memory
    for (((input_key_element, mut keyswitch_key_block), mask_chunk), noise_chunk) in input_lwe_sk
        .as_ref()
        .iter()
        .zip(lwe_keyswitch_key.iter_mut())
        .zip(mask_vector.iter())
        .zip(noise_vector.iter())
    {
        // We fill the buffer with the powers of the key elements
        for (level, message) in (1..=decomp_level_count.0)
            .map(DecompositionLevel)
            .rev()
            .zip(decomposition_plaintexts_buffer.iter_mut())
        {
            // Here  we take the decomposition term from the native torus, bring it to the torus we
            // are working with by dividing by the scaling factor and the encryption will take care
            // of mapping that back to the native torus
            *message.0 = DecompositionTerm::new(level, decomp_base_log, *input_key_element)
                .to_recomposition_summand()
                .wrapping_div(ciphertext_modulus.get_power_of_two_scaling_to_native_torus());
        }

        // let (tmp_mask_chunk, tmp_noise_chunk) =encrypt_lwe_ciphertext_list_ret_mask_and_noise(
        encrypt_lwe_ciphertext_list_deterministic(
            output_lwe_sk,
            &mut keyswitch_key_block,
            &decomposition_plaintexts_buffer,
            noise_distribution,
            generator,
            &mask_chunk,
            &noise_chunk,
        );
        // mask_chunk.as_mut().copy_from_slice(tmp_mask_chunk.as_ref());
        // noise_chunk.as_mut().copy_from_slice(tmp_noise_chunk.as_ref());
    }

    // (mask_vector, noise_vector)
}


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

impl <Scalar: UnsignedInteger> PublicKeyRandomVectors<Scalar> {
    fn new(init_val: Scalar, length: u64) -> Self {
        PublicKeyRandomVectors {
            binary_random_vector : vec![init_val; length.try_into().unwrap()]
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

pub fn encrypt_lwe_ciphertext_with_public_key_deterministic<Scalar, KeyCont, OutputCont>(
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

pub fn allocate_and_generate_new_lwe_keyswitch_key_with_public_key<
    Scalar,
    // NoiseDistribution,
    InputKeyCont,
    OutputKeyCont,
    Gen,
>(
    input_lwe_sk: &LweSecretKey<InputKeyCont>,
    // output_lwe_sk: &LweSecretKey<OutputKeyCont>,
    output_lwe_pk: &LwePublicKey<OutputKeyCont>,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    // noise_distribution: NoiseDistribution,
    ciphertext_modulus: CiphertextModulus<Scalar>,
    // pk_generator: &mut EncryptionRandomGenerator<Gen>,
    sk_generator: &mut SecretRandomGenerator<Gen>,
) -> LweKeyswitchKeyOwned<Scalar>
where
    Scalar: UnsignedTorus,
    // Scalar: Encryptable<Uniform, NoiseDistribution> + UnsignedTorus,
    // Scalar: Encryptable<Uniform, NoiseDistribution>,
    // NoiseDistribution: Distribution,
    InputKeyCont: Container<Element = Scalar>,
    OutputKeyCont: Container<Element = Scalar> + Sync,
    Gen: ByteRandomGenerator + ParallelByteRandomGenerator,
{
    let mut new_lwe_keyswitch_key = LweKeyswitchKeyOwned::new(
        Scalar::ZERO,
        decomp_base_log,
        decomp_level_count,
        input_lwe_sk.lwe_dimension(),
        // output_lwe_sk.lwe_dimension(),
        output_lwe_pk.lwe_size().to_lwe_dimension(),
        ciphertext_modulus,
    );

    // generate_lwe_keyswitch_key(
    //     input_lwe_sk,
    //     output_lwe_sk,
    //     &mut new_lwe_keyswitch_key,
    //     noise_distribution,
    //     pk_generator,
    // );

    generate_lwe_keyswitch_key_with_public_key(
        input_lwe_sk,
        // output_lwe_sk,
        output_lwe_pk,
        &mut new_lwe_keyswitch_key,
        // noise_distribution,
        // pk_generator,
        sk_generator,
    );

    new_lwe_keyswitch_key
}

pub fn generate_lwe_keyswitch_key_with_public_key<
    Scalar,
    // NoiseDistribution,
    InputKeyCont,
    OutputKeyCont,
    KSKeyCont,
    Gen,
>(
    input_lwe_sk: &LweSecretKey<InputKeyCont>,
    // output_lwe_sk: &LweSecretKey<OutputKeyCont>,
    output_lwe_pk: &LwePublicKey<OutputKeyCont>,
    lwe_keyswitch_key: &mut LweKeyswitchKey<KSKeyCont>,
    // noise_distribution: NoiseDistribution,
    // pk_generator: &mut EncryptionRandomGenerator<Gen>,
    sk_generator: &mut SecretRandomGenerator<Gen>,
) where
    Scalar: UnsignedTorus,
    // Scalar: Encryptable<Uniform, NoiseDistribution>,
    // Scalar: Encryptable<Uniform, NoiseDistribution> + UnsignedTorus,
    // NoiseDistribution: Distribution,
    InputKeyCont: Container<Element = Scalar>,
    OutputKeyCont: Container<Element = Scalar> + Sync,
    KSKeyCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator + ParallelByteRandomGenerator,
{
    let ciphertext_modulus = lwe_keyswitch_key.ciphertext_modulus();

    if !ciphertext_modulus.is_compatible_with_native_modulus() {
        println!("NOT IMPLEMENTED: ciphertext_modulus NOT compatible with native modulus case");
    }

    generate_lwe_keyswitch_key_with_public_key_native_mod_compatible(
        input_lwe_sk,
        // output_lwe_sk,
        output_lwe_pk,
        lwe_keyswitch_key,
        // noise_distribution,
        // pk_generator,
        sk_generator,
    )
}

pub fn generate_lwe_keyswitch_key_with_public_key_native_mod_compatible<
    Scalar,
    // NoiseDistribution,
    InputKeyCont,
    OutputKeyCont,
    KSKeyCont,
    Gen,
>(
    input_lwe_sk: &LweSecretKey<InputKeyCont>,
    // output_lwe_sk: &LweSecretKey<OutputKeyCont>,
    output_lwe_pk: &LwePublicKey<OutputKeyCont>,
    lwe_keyswitch_key: &mut LweKeyswitchKey<KSKeyCont>,
    // noise_distribution: NoiseDistribution,
    // pk_generator: &mut EncryptionRandomGenerator<Gen>,
    sk_generator: &mut SecretRandomGenerator<Gen>,
) where
    Scalar: UnsignedTorus,
    // Scalar: Encryptable<Uniform, NoiseDistribution>,
    // Scalar: Encryptable<Uniform, NoiseDistribution> + UnsignedTorus,
    // NoiseDistribution: Distribution,
    InputKeyCont: Container<Element = Scalar>,
    OutputKeyCont: Container<Element = Scalar> + Sync,
    KSKeyCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator + ParallelByteRandomGenerator,
{
    assert!(
        lwe_keyswitch_key.input_key_lwe_dimension() == input_lwe_sk.lwe_dimension(),
        "The destination LweKeyswitchKey input LweDimension is not equal \
    to the input LweSecretKey LweDimension. Destination: {:?}, input: {:?}",
        lwe_keyswitch_key.input_key_lwe_dimension(),
        input_lwe_sk.lwe_dimension()
    );
    assert!(
        lwe_keyswitch_key.output_key_lwe_dimension() == output_lwe_pk.lwe_size().to_lwe_dimension(),
        "The destination LweKeyswitchKey output LweDimension is not equal \
    to the output LwePublicKey LweDimension. Destination: {:?}, output: {:?}",
        lwe_keyswitch_key.output_key_lwe_dimension(),
        output_lwe_pk.lwe_size().to_lwe_dimension()
    );

    let decomp_base_log = lwe_keyswitch_key.decomposition_base_log();
    let decomp_level_count = lwe_keyswitch_key.decomposition_level_count();
    let ciphertext_modulus = lwe_keyswitch_key.ciphertext_modulus();
    assert!(ciphertext_modulus.is_compatible_with_native_modulus());

    let gen_iter = sk_generator
        // .try_fork_from_config(output.encryption_fork_config(Uniform, noise_distribution))
        // .try_fork_from_config(output.encryption_fork_config(Uniform, Uniform))
        .par_try_fork_from_config(lwe_keyswitch_key.encryption_fork_config_with_public_key(lwe_keyswitch_key.input_key_lwe_dimension(), decomp_level_count, output_lwe_pk.zero_encryption_count()))
        .unwrap();

    // Iterate over the input key elements and the destination lwe_keyswitch_key memory
    input_lwe_sk
        .as_ref().par_iter()
        .zip(lwe_keyswitch_key.par_iter_mut())
        .zip(gen_iter)
        .for_each(|((input_key_element, mut keyswitch_key_block), mut generator)| {

            // The plaintexts used to encrypt a key element will be stored in this buffer
            let mut decomposition_plaintexts_buffer =
                PlaintextListOwned::new(Scalar::ZERO, PlaintextCount(decomp_level_count.0));

            // We fill the buffer with the powers of the key elements
            for (level, message) in (1..=decomp_level_count.0)
                .map(DecompositionLevel)
                .rev()
                .zip(decomposition_plaintexts_buffer.iter_mut())
            {
                // Here  we take the decomposition term from the native torus, bring it to the torus we
                // are working with by dividing by the scaling factor and the encryption will take care
                // of mapping that back to the native torus
                *message.0 = DecompositionTerm::new(level, decomp_base_log, *input_key_element)
                    .to_recomposition_summand()
                    .wrapping_div(ciphertext_modulus.get_power_of_two_scaling_to_native_torus());
            }

            // println!("Calling encrypt_lwe_ciphertext_list_with_public_key...");
            // println!("Calling encrypt_lwe_ciphertext_list_with_public_key (counter = {:?})...", counter);
            // counter += 1;
            // encrypt_lwe_ciphertext_list_with_public_key(
            par_encrypt_lwe_ciphertext_list_with_public_key(
                output_lwe_pk,
                &mut keyswitch_key_block,
                &decomposition_plaintexts_buffer,
                // noise_distribution,
                &mut generator,
            );
        });

    // // The plaintexts used to encrypt a key element will be stored in this buffer
    // let mut decomposition_plaintexts_buffer =
    //     PlaintextListOwned::new(Scalar::ZERO, PlaintextCount(decomp_level_count.0));

    // // let mut counter = 0;
    // for (input_key_element, mut keyswitch_key_block) in input_lwe_sk
    //     .as_ref()
    //     .iter()
    //     .zip(lwe_keyswitch_key.iter_mut())
    // {
    //     // We fill the buffer with the powers of the key elements
    //     for (level, message) in (1..=decomp_level_count.0)
    //         .map(DecompositionLevel)
    //         .rev()
    //         .zip(decomposition_plaintexts_buffer.iter_mut())
    //     {
    //         // Here  we take the decomposition term from the native torus, bring it to the torus we
    //         // are working with by dividing by the scaling factor and the encryption will take care
    //         // of mapping that back to the native torus
    //         *message.0 = DecompositionTerm::new(level, decomp_base_log, *input_key_element)
    //             .to_recomposition_summand()
    //             .wrapping_div(ciphertext_modulus.get_power_of_two_scaling_to_native_torus());
    //     }

    //     // println!("Calling encrypt_lwe_ciphertext_list_with_public_key...");
    //     // println!("Calling encrypt_lwe_ciphertext_list_with_public_key (counter = {:?})...", counter);
    //     // println!("plaintext: {:?}", decomposition_plaintexts_buffer.as_ref());
    //     // counter += 1;

    //     // encrypt_lwe_ciphertext_list(
    //     //     output_lwe_sk,
    //     //     &mut keyswitch_key_block,
    //     //     &decomposition_plaintexts_buffer,
    //     //     noise_distribution,
    //     //     pk_generator,
    //     // );

    //     // encrypt_lwe_ciphertext_list_with_public_key(
    //     //     output_lwe_sk,
    //     //     output_lwe_pk,
    //     //     &mut keyswitch_key_block,
    //     //     &decomposition_plaintexts_buffer,
    //     //     noise_distribution,
    //     //     pk_generator,
    //     //     sk_generator,
    //     // );

    //     par_encrypt_lwe_ciphertext_list_with_public_key(
    //         output_lwe_pk,
    //         &mut keyswitch_key_block,
    //         &decomposition_plaintexts_buffer,
    //         sk_generator,
    //     );

    // }
}

pub fn encrypt_lwe_ciphertext_list_with_public_key<Scalar, KeyCont, OutputCont, InputCont, Gen>(
    // lwe_secret_key: &LweSecretKey<KeyCont>,
    lwe_public_key: &LwePublicKey<KeyCont>,
    output: &mut LweCiphertextList<OutputCont>,
    encoded: &PlaintextList<InputCont>,
    // noise_distribution: NoiseDistribution,
    // pk_generator: &mut EncryptionRandomGenerator<Gen>,
    sk_generator: &mut SecretRandomGenerator<Gen>,
) where
    Scalar: UnsignedTorus,
    // Scalar: Encryptable<Uniform, NoiseDistribution>,
    // Scalar: Encryptable<Uniform, NoiseDistribution> + UnsignedTorus,
    KeyCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    Gen: ByteRandomGenerator,
    // NoiseDistribution: Distribution,
{
    assert!(
        output.lwe_ciphertext_count().0 == encoded.plaintext_count().0,
        "Mismatch between number of output ciphertexts and input plaintexts. \
        Got {:?} plaintexts, and {:?} ciphertext.",
        encoded.plaintext_count(),
        output.lwe_ciphertext_count()
    );

    // let gen_iter = generator
    //     // .try_fork_from_config(output.encryption_fork_config(Uniform, noise_distribution))
    //     // .try_fork_from_config(output.encryption_fork_config(Uniform, Uniform))
    //     .try_fork_from_config(output.encryption_fork_config_with_public_key(lwe_public_key.zero_encryption_count()))
    //     .unwrap();

    // let mut counter = 0;
    // for ((encoded_plaintext_ref, mut ciphertext), mut loop_generator) in
    for (encoded_plaintext_ref, mut ciphertext) in
        encoded
        .iter()
        .zip(output.iter_mut())
        // .zip(gen_iter)
    {
        // println!("Calling encrypt_lwe_ciphertext_with_public_key (counter = {:?})...", counter);
        // counter += 1;

        // encrypt_lwe_ciphertext(
        //     lwe_secret_key,
        //     &mut ciphertext,
        //     encoded_plaintext_ref.into(),
        //     noise_distribution,
        //     pk_generator,
        //     // &mut loop_generator,
        // );

        encrypt_lwe_ciphertext_with_public_key(
            lwe_public_key,
            &mut ciphertext,
            encoded_plaintext_ref.into(),
            // noise_distribution,
            sk_generator,
            // &mut loop_generator,
            // &mut loop_generator.mask.gen,
            // &mut SecretRandomGenerator::new(loop_generator.mask.gen.seed()),
        );
    }
}

pub fn par_encrypt_lwe_ciphertext_list_with_public_key<
    Scalar,
    // NoiseDistribution,
    KeyCont,
    OutputCont,
    InputCont,
    Gen,
>(
    lwe_public_key: &LwePublicKey<KeyCont>,
    // lwe_secret_key: &LweSecretKey<KeyCont>,
    output: &mut LweCiphertextList<OutputCont>,
    encoded: &PlaintextList<InputCont>,
    // noise_distribution: NoiseDistribution,
    // generator: &mut EncryptionRandomGenerator<Gen>,
    generator: &mut SecretRandomGenerator<Gen>,
) where
    Scalar: UnsignedTorus + Sync,
    // Scalar: Encryptable<Uniform, NoiseDistribution> + Sync + Send,
    // NoiseDistribution: Distribution + Sync,
    KeyCont: Container<Element = Scalar> + Sync,
    OutputCont: ContainerMut<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    Gen: ParallelByteRandomGenerator,
{
    assert!(
        output.lwe_ciphertext_count().0 == encoded.plaintext_count().0,
        "Mismatch between number of output ciphertexts and input plaintexts. \
        Got {:?} plaintexts, and {:?} ciphertext.",
        encoded.plaintext_count(),
        output.lwe_ciphertext_count()
    );

    let gen_iter = generator
        .par_try_fork_from_config(output.encryption_fork_config_with_public_key(lwe_public_key.zero_encryption_count()))
        // .par_try_fork_from_config(output.encryption_fork_config(Uniform, noise_distribution))
        .unwrap();

    encoded
        .par_iter()
        .zip(output.par_iter_mut())
        .zip(gen_iter)
        .for_each(|((encoded_plaintext_ref, mut ciphertext), mut generator)| {
            encrypt_lwe_ciphertext_with_public_key(
                // lwe_secret_key,
                lwe_public_key,
                &mut ciphertext,
                encoded_plaintext_ref.into(),
                // noise_distribution,
                &mut generator,
            );
        });
}


pub fn allocate_and_generate_new_lwe_keyswitch_key_with_public_key_ret_mask<
    Scalar,
    InputKeyCont,
    OutputKeyCont,
    Gen,
>(
    input_lwe_sk: &LweSecretKey<InputKeyCont>,
    output_lwe_pk: &LwePublicKey<OutputKeyCont>,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    ciphertext_modulus: CiphertextModulus<Scalar>,
    sk_generator: &mut SecretRandomGenerator<Gen>,
// ) -> LweKeyswitchKeyOwned<Scalar>
) -> (LweKeyswitchKeyOwned<Scalar>, Vec<Vec<PublicKeyRandomVectors<Scalar>>>, Vec<PlaintextListOwned<Scalar>>)
where
    Scalar: UnsignedTorus,
    InputKeyCont: Container<Element = Scalar>,
    OutputKeyCont: Container<Element = Scalar> + Sync,
    Gen: ByteRandomGenerator + ParallelByteRandomGenerator,
{
    let mut new_lwe_keyswitch_key = LweKeyswitchKeyOwned::new(
        Scalar::ZERO,
        decomp_base_log,
        decomp_level_count,
        input_lwe_sk.lwe_dimension(),
        output_lwe_pk.lwe_size().to_lwe_dimension(),
        ciphertext_modulus,
    );

    let (ksk_mask_vector, plaintexts_vector) = generate_lwe_keyswitch_key_with_public_key_ret_mask(
        input_lwe_sk,
        output_lwe_pk,
        &mut new_lwe_keyswitch_key,
        sk_generator,
    );

    (new_lwe_keyswitch_key, ksk_mask_vector, plaintexts_vector)
}

pub fn generate_lwe_keyswitch_key_with_public_key_ret_mask<
    Scalar,
    InputKeyCont,
    OutputKeyCont,
    KSKeyCont,
    Gen,
>(
    input_lwe_sk: &LweSecretKey<InputKeyCont>,
    output_lwe_pk: &LwePublicKey<OutputKeyCont>,
    lwe_keyswitch_key: &mut LweKeyswitchKey<KSKeyCont>,
    sk_generator: &mut SecretRandomGenerator<Gen>,
// ) 
) -> (Vec<Vec<PublicKeyRandomVectors<Scalar>>>, Vec<PlaintextListOwned<Scalar>>)
where
    Scalar: UnsignedTorus,
    InputKeyCont: Container<Element = Scalar>,
    OutputKeyCont: Container<Element = Scalar> + Sync,
    KSKeyCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator + ParallelByteRandomGenerator,
{
    let ciphertext_modulus = lwe_keyswitch_key.ciphertext_modulus();

    if !ciphertext_modulus.is_compatible_with_native_modulus() {
        println!("NOT IMPLEMENTED: ciphertext_modulus NOT compatible with native modulus case");
    }

    generate_lwe_keyswitch_key_with_public_key_native_mod_compatible_ret_mask(
        input_lwe_sk,
        output_lwe_pk,
        lwe_keyswitch_key,
        sk_generator,
    )
}

pub fn generate_lwe_keyswitch_key_with_public_key_native_mod_compatible_ret_mask<
    Scalar,
    InputKeyCont,
    OutputKeyCont,
    KSKeyCont,
    Gen,
>(
    input_lwe_sk: &LweSecretKey<InputKeyCont>,
    output_lwe_pk: &LwePublicKey<OutputKeyCont>,
    lwe_keyswitch_key: &mut LweKeyswitchKey<KSKeyCont>,
    sk_generator: &mut SecretRandomGenerator<Gen>,
// ) 
) -> (Vec<Vec<PublicKeyRandomVectors<Scalar>>>, Vec<PlaintextListOwned<Scalar>>)
where
    Scalar: UnsignedTorus,
    InputKeyCont: Container<Element = Scalar>,
    OutputKeyCont: Container<Element = Scalar> + Sync,
    KSKeyCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator + ParallelByteRandomGenerator,
{
    assert!(
        lwe_keyswitch_key.input_key_lwe_dimension() == input_lwe_sk.lwe_dimension(),
        "The destination LweKeyswitchKey input LweDimension is not equal \
    to the input LweSecretKey LweDimension. Destination: {:?}, input: {:?}",
        lwe_keyswitch_key.input_key_lwe_dimension(),
        input_lwe_sk.lwe_dimension()
    );
    assert!(
        lwe_keyswitch_key.output_key_lwe_dimension() == output_lwe_pk.lwe_size().to_lwe_dimension(),
        "The destination LweKeyswitchKey output LweDimension is not equal \
    to the output LwePublicKey LweDimension. Destination: {:?}, output: {:?}",
        lwe_keyswitch_key.output_key_lwe_dimension(),
        output_lwe_pk.lwe_size().to_lwe_dimension()
    );

    let decomp_base_log = lwe_keyswitch_key.decomposition_base_log();
    let decomp_level_count = lwe_keyswitch_key.decomposition_level_count();
    let ciphertext_modulus = lwe_keyswitch_key.ciphertext_modulus();
    assert!(ciphertext_modulus.is_compatible_with_native_modulus());

    let gen_iter = sk_generator
        .par_try_fork_from_config(lwe_keyswitch_key.encryption_fork_config_with_public_key(lwe_keyswitch_key.input_key_lwe_dimension(), decomp_level_count, output_lwe_pk.zero_encryption_count()))
        .unwrap();

    // The plaintexts used to encrypt a key element will be stored in this buffer
    let mut decomposition_plaintexts_buffer_vector =
        vec![
            PlaintextListOwned::new(Scalar::ZERO, PlaintextCount(decomp_level_count.0));
            lwe_keyswitch_key.input_key_lwe_dimension().0
        ];

    // let mut new_ciphertext_modulus = CiphertextModulus::<Scalar>::new_native();
    // if !ciphertext_modulus.is_native_modulus() {
    //     new_ciphertext_modulus = CiphertextModulus::<Scalar>::new(ciphertext_modulus.get_custom_modulus());
    // }
    let mut mask_vector = 
        vec![
            vec![
                PublicKeyRandomVectors::new(Scalar::ZERO, output_lwe_pk.zero_encryption_count().0.try_into().unwrap());
                // LweMask::from_container(
                //     vec![
                //         Scalar::ZERO; 
                //         lwe_keyswitch_key.output_key_lwe_dimension().0
                //     ], 
                //     new_ciphertext_modulus);
                decomp_level_count.0
            ];
            lwe_keyswitch_key.input_key_lwe_dimension().0
        ];

    // Iterate over the input key elements and the destination lwe_keyswitch_key memory
    input_lwe_sk
        .as_ref().par_iter()
        .zip(lwe_keyswitch_key.par_iter_mut())
        .zip(gen_iter)
        .zip(mask_vector.par_iter_mut())
        .zip(decomposition_plaintexts_buffer_vector.par_iter_mut())
        .for_each(|((((input_key_element, mut keyswitch_key_block), mut generator), mask_chunk), decomposition_plaintexts_buffer)| {

            // We fill the buffer with the powers of the key elements
            for (level, message) in (1..=decomp_level_count.0)
                .map(DecompositionLevel)
                .rev()
                .zip(decomposition_plaintexts_buffer.iter_mut())
            {
                // Here  we take the decomposition term from the native torus, bring it to the torus we
                // are working with by dividing by the scaling factor and the encryption will take care
                // of mapping that back to the native torus
                *message.0 = DecompositionTerm::new(level, decomp_base_log, *input_key_element)
                    .to_recomposition_summand()
                    .wrapping_div(ciphertext_modulus.get_power_of_two_scaling_to_native_torus());
            }

            *mask_chunk = par_encrypt_lwe_ciphertext_list_with_public_key_ret_mask(
                output_lwe_pk,
                &mut keyswitch_key_block,
                &decomposition_plaintexts_buffer,
                &mut generator,
            );
        });

    (mask_vector, decomposition_plaintexts_buffer_vector)
}

pub fn par_encrypt_lwe_ciphertext_list_with_public_key_ret_mask<
    Scalar,
    KeyCont,
    OutputCont,
    InputCont,
    Gen,
>(
    lwe_public_key: &LwePublicKey<KeyCont>,
    output: &mut LweCiphertextList<OutputCont>,
    encoded: &PlaintextList<InputCont>,
    generator: &mut SecretRandomGenerator<Gen>,
// ) 
// ) -> Vec<LweMask<Vec<Scalar>>>
) -> Vec<PublicKeyRandomVectors<Scalar>>
where
    Scalar: UnsignedTorus + Sync,
    KeyCont: Container<Element = Scalar> + Sync,
    OutputCont: ContainerMut<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    Gen: ParallelByteRandomGenerator,
{
    assert!(
        output.lwe_ciphertext_count().0 == encoded.plaintext_count().0,
        "Mismatch between number of output ciphertexts and input plaintexts. \
        Got {:?} plaintexts, and {:?} ciphertext.",
        encoded.plaintext_count(),
        output.lwe_ciphertext_count()
    );

    let gen_iter = generator
        .par_try_fork_from_config(output.encryption_fork_config_with_public_key(lwe_public_key.zero_encryption_count()))
        .unwrap();

    // let mut new_ciphertext_modulus = CiphertextModulus::<Scalar>::new_native();
    // if !output.ciphertext_modulus().is_native_modulus() {
    //     new_ciphertext_modulus = CiphertextModulus::<Scalar>::new(output.ciphertext_modulus().get_custom_modulus());
    // }
    // let mut mask_vector = vec![
    //     LweMask::from_container(
    //         vec![
    //             Scalar::ZERO; 
    //             output.lwe_size().to_lwe_dimension().0
    //         ], 
    //         new_ciphertext_modulus);
    //     output.lwe_ciphertext_count().0
    // ];
    let mut mask_vector = vec![
        PublicKeyRandomVectors::new(Scalar::ZERO, lwe_public_key.zero_encryption_count().0.try_into().unwrap());
        output.lwe_ciphertext_count().0
    ];

    encoded
        .par_iter()
        .zip(output.par_iter_mut())
        .zip(gen_iter)
        .zip(mask_vector.par_iter_mut())
        .for_each(|(((encoded_plaintext_ref, mut ciphertext), mut generator), mask_entry)| {
            let tmp_mask_entry = encrypt_lwe_ciphertext_with_public_key_ret_mask(
                lwe_public_key,
                &mut ciphertext,
                encoded_plaintext_ref.into(),
                &mut generator,
            );
            mask_entry.binary_random_vector = tmp_mask_entry.binary_random_vector;
        });

    mask_vector
}

pub fn allocate_and_generate_new_lwe_keyswitch_key_with_public_key_deterministic<
    Scalar,
    InputKeyCont,
    OutputKeyCont,
    // Gen,
>(
    input_lwe_sk: &LweSecretKey<InputKeyCont>,
    output_lwe_pk: &LwePublicKey<OutputKeyCont>,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    ciphertext_modulus: CiphertextModulus<Scalar>,
    // sk_generator: &mut SecretRandomGenerator<Gen>,
    ksk_mask_vector: &Vec<Vec<PublicKeyRandomVectors<Scalar>>>,
) -> LweKeyswitchKeyOwned<Scalar>
// ) -> (LweKeyswitchKeyOwned<Scalar>, Vec<Vec<PublicKeyRandomVectors<Scalar>>>, Vec<PlaintextListOwned<Scalar>>)
where
    Scalar: UnsignedTorus,
    InputKeyCont: Container<Element = Scalar>,
    OutputKeyCont: Container<Element = Scalar> + Sync,
    // Gen: ByteRandomGenerator + ParallelByteRandomGenerator,
{
    let mut new_lwe_keyswitch_key = LweKeyswitchKeyOwned::new(
        Scalar::ZERO,
        decomp_base_log,
        decomp_level_count,
        input_lwe_sk.lwe_dimension(),
        output_lwe_pk.lwe_size().to_lwe_dimension(),
        ciphertext_modulus,
    );

    generate_lwe_keyswitch_key_with_public_key_deterministic(
        input_lwe_sk,
        output_lwe_pk,
        &mut new_lwe_keyswitch_key,
        // sk_generator,
        ksk_mask_vector,
    );

    new_lwe_keyswitch_key
}

pub fn generate_lwe_keyswitch_key_with_public_key_deterministic<
    Scalar,
    InputKeyCont,
    OutputKeyCont,
    KSKeyCont,
    // Gen,
>(
    input_lwe_sk: &LweSecretKey<InputKeyCont>,
    output_lwe_pk: &LwePublicKey<OutputKeyCont>,
    lwe_keyswitch_key: &mut LweKeyswitchKey<KSKeyCont>,
    // sk_generator: &mut SecretRandomGenerator<Gen>,
    ksk_mask_vector: &Vec<Vec<PublicKeyRandomVectors<Scalar>>>,
) 
// ) -> (Vec<Vec<PublicKeyRandomVectors<Scalar>>>, Vec<PlaintextListOwned<Scalar>>)
where
    Scalar: UnsignedTorus,
    InputKeyCont: Container<Element = Scalar>,
    OutputKeyCont: Container<Element = Scalar> + Sync,
    KSKeyCont: ContainerMut<Element = Scalar>,
    // Gen: ByteRandomGenerator + ParallelByteRandomGenerator,
{
    let ciphertext_modulus = lwe_keyswitch_key.ciphertext_modulus();

    if !ciphertext_modulus.is_compatible_with_native_modulus() {
        println!("NOT IMPLEMENTED: ciphertext_modulus NOT compatible with native modulus case");
    }

    generate_lwe_keyswitch_key_with_public_key_native_mod_compatible_deterministic(
        input_lwe_sk,
        output_lwe_pk,
        lwe_keyswitch_key,
        // sk_generator,
        ksk_mask_vector,
    )
}

pub fn generate_lwe_keyswitch_key_with_public_key_native_mod_compatible_deterministic<
    Scalar,
    InputKeyCont,
    OutputKeyCont,
    KSKeyCont,
    // Gen,
>(
    input_lwe_sk: &LweSecretKey<InputKeyCont>,
    output_lwe_pk: &LwePublicKey<OutputKeyCont>,
    lwe_keyswitch_key: &mut LweKeyswitchKey<KSKeyCont>,
    // sk_generator: &mut SecretRandomGenerator<Gen>,
    mask_vector: &Vec<Vec<PublicKeyRandomVectors<Scalar>>>,
) 
// ) -> (Vec<Vec<PublicKeyRandomVectors<Scalar>>>, Vec<PlaintextListOwned<Scalar>>)
where
    Scalar: UnsignedTorus,
    InputKeyCont: Container<Element = Scalar>,
    OutputKeyCont: Container<Element = Scalar> + Sync,
    KSKeyCont: ContainerMut<Element = Scalar>,
    // Gen: ByteRandomGenerator + ParallelByteRandomGenerator,
{
    assert!(
        lwe_keyswitch_key.input_key_lwe_dimension() == input_lwe_sk.lwe_dimension(),
        "The destination LweKeyswitchKey input LweDimension is not equal \
    to the input LweSecretKey LweDimension. Destination: {:?}, input: {:?}",
        lwe_keyswitch_key.input_key_lwe_dimension(),
        input_lwe_sk.lwe_dimension()
    );
    assert!(
        lwe_keyswitch_key.output_key_lwe_dimension() == output_lwe_pk.lwe_size().to_lwe_dimension(),
        "The destination LweKeyswitchKey output LweDimension is not equal \
    to the output LwePublicKey LweDimension. Destination: {:?}, output: {:?}",
        lwe_keyswitch_key.output_key_lwe_dimension(),
        output_lwe_pk.lwe_size().to_lwe_dimension()
    );

    let decomp_base_log = lwe_keyswitch_key.decomposition_base_log();
    let decomp_level_count = lwe_keyswitch_key.decomposition_level_count();
    let ciphertext_modulus = lwe_keyswitch_key.ciphertext_modulus();
    assert!(ciphertext_modulus.is_compatible_with_native_modulus());

    // let gen_iter = sk_generator
    //     .par_try_fork_from_config(lwe_keyswitch_key.encryption_fork_config_with_public_key(lwe_keyswitch_key.input_key_lwe_dimension(), decomp_level_count, output_lwe_pk.zero_encryption_count()))
    //     .unwrap();

    // // The plaintexts used to encrypt a key element will be stored in this buffer
    // let mut decomposition_plaintexts_buffer_vector =
    //     vec![
    //         PlaintextListOwned::new(Scalar::ZERO, PlaintextCount(decomp_level_count.0));
    //         lwe_keyswitch_key.input_key_lwe_dimension().0
    //     ];

    // let mut new_ciphertext_modulus = CiphertextModulus::<Scalar>::new_native();
    // if !ciphertext_modulus.is_native_modulus() {
    //     new_ciphertext_modulus = CiphertextModulus::<Scalar>::new(ciphertext_modulus.get_custom_modulus());
    // }
    // let mut mask_vector = 
    //     vec![
    //         vec![
    //             PublicKeyRandomVectors::new(Scalar::ZERO, output_lwe_pk.zero_encryption_count().0.try_into().unwrap());
    //             // LweMask::from_container(
    //             //     vec![
    //             //         Scalar::ZERO; 
    //             //         lwe_keyswitch_key.output_key_lwe_dimension().0
    //             //     ], 
    //             //     new_ciphertext_modulus);
    //             decomp_level_count.0
    //         ];
    //         lwe_keyswitch_key.input_key_lwe_dimension().0
    //     ];

    // Iterate over the input key elements and the destination lwe_keyswitch_key memory
    input_lwe_sk
        .as_ref().par_iter()
        .zip(lwe_keyswitch_key.par_iter_mut())
        // .zip(gen_iter)
        .zip(mask_vector.par_iter())
        // .for_each(|(((input_key_element, mut keyswitch_key_block), mut generator), mask_chunk)| {
        .for_each(|((input_key_element, mut keyswitch_key_block), mask_chunk)| {

            // The plaintexts used to encrypt a key element will be stored in this buffer
            let mut decomposition_plaintexts_buffer =
                PlaintextListOwned::new(Scalar::ZERO, PlaintextCount(decomp_level_count.0));

            // We fill the buffer with the powers of the key elements
            for (level, message) in (1..=decomp_level_count.0)
                .map(DecompositionLevel)
                .rev()
                .zip(decomposition_plaintexts_buffer.iter_mut())
            {
                // Here  we take the decomposition term from the native torus, bring it to the torus we
                // are working with by dividing by the scaling factor and the encryption will take care
                // of mapping that back to the native torus
                *message.0 = DecompositionTerm::new(level, decomp_base_log, *input_key_element)
                    .to_recomposition_summand()
                    .wrapping_div(ciphertext_modulus.get_power_of_two_scaling_to_native_torus());
            }

            par_encrypt_lwe_ciphertext_list_with_public_key_deterministic(
                output_lwe_pk,
                &mut keyswitch_key_block,
                &decomposition_plaintexts_buffer,
                // &mut generator,
                &mask_chunk,
            );
        });

    // (mask_vector, decomposition_plaintexts_buffer_vector)
}

pub fn par_encrypt_lwe_ciphertext_list_with_public_key_deterministic<
    Scalar,
    KeyCont,
    OutputCont,
    InputCont,
    // Gen,
>(
    lwe_public_key: &LwePublicKey<KeyCont>,
    output: &mut LweCiphertextList<OutputCont>,
    encoded: &PlaintextList<InputCont>,
    // generator: &mut SecretRandomGenerator<Gen>,
    mask_vector: &Vec<PublicKeyRandomVectors<Scalar>>,
) 
// ) -> Vec<LweMask<Vec<Scalar>>>
// ) -> Vec<PublicKeyRandomVectors<Scalar>>
where
    Scalar: UnsignedTorus + Sync,
    KeyCont: Container<Element = Scalar> + Sync,
    OutputCont: ContainerMut<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    // Gen: ParallelByteRandomGenerator,
{
    assert!(
        output.lwe_ciphertext_count().0 == encoded.plaintext_count().0,
        "Mismatch between number of output ciphertexts and input plaintexts. \
        Got {:?} plaintexts, and {:?} ciphertext.",
        encoded.plaintext_count(),
        output.lwe_ciphertext_count()
    );

    // let gen_iter = generator
    //     .par_try_fork_from_config(output.encryption_fork_config_with_public_key(lwe_public_key.zero_encryption_count()))
    //     .unwrap();

    // let mut new_ciphertext_modulus = CiphertextModulus::<Scalar>::new_native();
    // if !output.ciphertext_modulus().is_native_modulus() {
    //     new_ciphertext_modulus = CiphertextModulus::<Scalar>::new(output.ciphertext_modulus().get_custom_modulus());
    // }
    // let mut mask_vector = vec![
    //     LweMask::from_container(
    //         vec![
    //             Scalar::ZERO; 
    //             output.lwe_size().to_lwe_dimension().0
    //         ], 
    //         new_ciphertext_modulus);
    //     output.lwe_ciphertext_count().0
    // ];
    // let mut mask_vector = vec![
    //     PublicKeyRandomVectors::new(Scalar::ZERO, lwe_public_key.zero_encryption_count().0.try_into().unwrap());
    //     output.lwe_ciphertext_count().0
    // ];

    encoded
        .par_iter()
        .zip(output.par_iter_mut())
        // .zip(gen_iter)
        .zip(mask_vector.par_iter())
        // .for_each(|(((encoded_plaintext_ref, mut ciphertext), mut generator), mask_entry)| {
        .for_each(|((encoded_plaintext_ref, mut ciphertext), mask_entry)| {
            encrypt_lwe_ciphertext_with_public_key_deterministic(
                lwe_public_key,
                &mut ciphertext,
                encoded_plaintext_ref.into(),
                // &mut generator,
                mask_entry.binary_random_vector.clone(),
            );
        });
}

pub fn keyswitch_lwe_ciphertext_ret_mask<Scalar, KSKCont, InputCont, OutputCont>(
    lwe_keyswitch_key: &LweKeyswitchKey<KSKCont>,
    input_lwe_ciphertext: &LweCiphertext<InputCont>,
    output_lwe_ciphertext: &mut LweCiphertext<OutputCont>,
    // ksk_noise_vector: &Vec<Vec<LweBody<Scalar>>>,
    ksk_mask_vector: &Vec<Vec<PublicKeyRandomVectors<Scalar>>>,
    plaintextlist_vector: &Vec<PlaintextListOwned<Scalar>>,
// ) -> LweBody<Scalar>
// ) -> (LweBody<Scalar>, Plaintext<Scalar>)
) -> (PublicKeyRandomVectors<Scalar>, Plaintext<Scalar>)
where
    Scalar: UnsignedInteger,
    KSKCont: Container<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
{
    let ciphertext_modulus = lwe_keyswitch_key.ciphertext_modulus();

    if !ciphertext_modulus.is_compatible_with_native_modulus() {
        println!("NOT IMPLEMENTED: ciphertext_modulus NOT compatible with native modulus case");
    }
    keyswitch_lwe_ciphertext_native_mod_compatible_ret_mask(
        lwe_keyswitch_key,
        input_lwe_ciphertext,
        output_lwe_ciphertext,
        // ksk_noise_vector,
        ksk_mask_vector,
        plaintextlist_vector,
    )
}

pub fn keyswitch_lwe_ciphertext_native_mod_compatible_ret_mask<Scalar, KSKCont, InputCont, OutputCont>(
    lwe_keyswitch_key: &LweKeyswitchKey<KSKCont>,
    input_lwe_ciphertext: &LweCiphertext<InputCont>,
    output_lwe_ciphertext: &mut LweCiphertext<OutputCont>,
    // ksk_noise_vector: &Vec<Vec<LweBody<Scalar>>>,
    ksk_mask_vector: &Vec<Vec<PublicKeyRandomVectors<Scalar>>>,
    plaintextlist_vector: &Vec<PlaintextListOwned<Scalar>>,
// ) -> LweBody<Scalar>
// ) -> (LweBody<Scalar>, Plaintext<Scalar>)
) -> (PublicKeyRandomVectors<Scalar>, Plaintext<Scalar>)
where
    Scalar: UnsignedInteger,
    KSKCont: Container<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
{
    assert!(
        lwe_keyswitch_key.input_key_lwe_dimension()
            == input_lwe_ciphertext.lwe_size().to_lwe_dimension(),
        "Mismatched input LweDimension. \
        LweKeyswitchKey input LweDimension: {:?}, input LweCiphertext LweDimension {:?}.",
        lwe_keyswitch_key.input_key_lwe_dimension(),
        input_lwe_ciphertext.lwe_size().to_lwe_dimension(),
    );
    assert!(
        lwe_keyswitch_key.output_key_lwe_dimension()
            == output_lwe_ciphertext.lwe_size().to_lwe_dimension(),
        "Mismatched output LweDimension. \
        LweKeyswitchKey output LweDimension: {:?}, output LweCiphertext LweDimension {:?}.",
        lwe_keyswitch_key.output_key_lwe_dimension(),
        output_lwe_ciphertext.lwe_size().to_lwe_dimension(),
    );

    let output_ciphertext_modulus = output_lwe_ciphertext.ciphertext_modulus();

    assert_eq!(
        lwe_keyswitch_key.ciphertext_modulus(),
        output_ciphertext_modulus,
        "Mismatched CiphertextModulus. \
        LweKeyswitchKey CiphertextModulus: {:?}, output LweCiphertext CiphertextModulus {:?}.",
        lwe_keyswitch_key.ciphertext_modulus(),
        output_ciphertext_modulus
    );
    assert!(
        output_ciphertext_modulus.is_compatible_with_native_modulus(),
        "This operation currently only supports power of 2 moduli"
    );

    let input_ciphertext_modulus = input_lwe_ciphertext.ciphertext_modulus();

    assert!(
        input_ciphertext_modulus.is_compatible_with_native_modulus(),
        "This operation currently only supports power of 2 moduli"
    );

    // Clear the output ciphertext, as it will get updated gradually
    output_lwe_ciphertext.as_mut().fill(Scalar::ZERO);

    let mut new_ciphertext_modulus = CiphertextModulus::<Scalar>::new_native();
    if !output_ciphertext_modulus.is_native_modulus() {
        new_ciphertext_modulus = CiphertextModulus::<Scalar>::new(output_ciphertext_modulus.get_custom_modulus());
    }
    // let mut output_lwe_ciphertext_noise = LweBody::new(Scalar::ZERO, new_ciphertext_modulus);
    let mut output_lwe_ciphertext_mask = PublicKeyRandomVectors::new(Scalar::ZERO, ksk_mask_vector[0][0].binary_random_vector.len().try_into().unwrap());
    let mut noisy_message = Scalar::ZERO;

    // Copy the input body to the output ciphertext
    *output_lwe_ciphertext.get_mut_body().data = *input_lwe_ciphertext.get_body().data;

    // If the moduli are not the same, we need to round the body in the output ciphertext
    if output_ciphertext_modulus != input_ciphertext_modulus
        && !output_ciphertext_modulus.is_native_modulus()
    {
        let modulus_bits = output_ciphertext_modulus.get_custom_modulus().ilog2() as usize;
        let output_decomposer = SignedDecomposer::new(
            DecompositionBaseLog(modulus_bits),
            DecompositionLevelCount(1),
        );

        *output_lwe_ciphertext.get_mut_body().data =
            output_decomposer.closest_representable(*output_lwe_ciphertext.get_mut_body().data);
    }
    // start computing noisy message
    noisy_message = *output_lwe_ciphertext.get_body().data;

    // We instantiate a decomposer
    let decomposer = SignedDecomposer::new(
        lwe_keyswitch_key.decomposition_base_log(),
        lwe_keyswitch_key.decomposition_level_count(),
    );

    for (((keyswitch_key_block, &input_mask_element), ksk_mask_chunk), plaintextlist) in lwe_keyswitch_key
        .iter()
        .zip(input_lwe_ciphertext.get_mask().as_ref())
        .zip(ksk_mask_vector.iter())
        .zip(plaintextlist_vector.iter())
    {
        let decomposition_iter = decomposer.decompose(input_mask_element);
        // Loop over the levels
        for (((level_key_ciphertext, decomposed), ksk_mask_entry), plaintext) in keyswitch_key_block
            .iter()
            .zip(decomposition_iter)
            .zip(ksk_mask_chunk.iter())
            .zip(plaintextlist.as_ref())
        {
            slice_wrapping_sub_scalar_mul_assign(
                output_lwe_ciphertext.as_mut(),
                level_key_ciphertext.as_ref(),
                decomposed.value(),
            );
            // compute mask
            slice_wrapping_sub_scalar_mul_assign(
                &mut output_lwe_ciphertext_mask.binary_random_vector,
                &ksk_mask_entry.binary_random_vector,
                decomposed.value(),
            );
            // let tmp_val = ksk_noise_entry.data;
            // output_lwe_ciphertext_noise.data = output_lwe_ciphertext_noise.data.wrapping_sub(
            //     tmp_val.wrapping_mul(decomposed.value())
            // );

            // compute noisy message
            let tmp_noisy_message = plaintext;
            noisy_message = noisy_message.wrapping_sub(
                tmp_noisy_message.wrapping_mul(decomposed.value())
            );
        }
    }
    (output_lwe_ciphertext_mask, Plaintext(noisy_message))
}
