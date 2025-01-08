#![allow(unused_imports)]

// use super::*;
// use crate::core_crypto::commons::generators::DeterministicSeeder;
// #[cfg(feature = "zk-pok")]
// use crate::core_crypto::commons::math::random::RandomGenerator;
// use crate::core_crypto::commons::test_tools;
// #[cfg(feature = "zk-pok")]
// use rand::Rng;

use tfhe::core_crypto::prelude::*;
// use tfhe::core_crypto::commons::generators::DeterministicSeeder;
#[cfg(feature = "zk-pok")]
use tfhe::core_crypto::commons::math::random::RandomGenerator;
#[cfg(test)]
use tfhe::core_crypto::commons::test_tools;
#[cfg(feature = "zk-pok")]
use rand::Rng;
use tfhe::safe_serialization::safe_serialize;
use tfhe::core_crypto::prelude::slice_algorithms::slice_wrapping_add;

use crate::lwe_encryption::*;

const NB_TESTS: usize = 1;

mod lwe_encryption;


// #[cfg(test)]
fn test_sk_enc() {
	println!("Testing encrypt_lwe_ciphertext");
    // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    // computations
    // Define parameters for LweCiphertext creation
    let lwe_dimension = LweDimension(742);
    let lwe_noise_distribution =
        DynamicDistribution::new_gaussian_from_std_dev(StandardDev(4.998_277_131_225_527e-11));

    // Create the PRNG
    let mut seeder = new_seeder();
    let seeder = seeder.as_mut();
    let mut encryption_generator =
        EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
    let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

    const MSG_BITS: u32 = 4;

    for _ in 0..NB_TESTS {
        for msg in 0..2u128.pow(MSG_BITS) {
            // Create the LweSecretKey
            let lwe_secret_key = allocate_and_generate_new_binary_lwe_secret_key(
                lwe_dimension,
                &mut secret_generator,
            );

            // Create the plaintext
            const ENCODING: u32 = u128::BITS - MSG_BITS;
            let plaintext = Plaintext(msg << ENCODING);

            // Create a new LweCiphertext
            let mut lwe = LweCiphertext::new(
                0u128,
                lwe_dimension.to_lwe_size(),
                CiphertextModulus::new_native(),
            );

            encrypt_lwe_ciphertext(
                &lwe_secret_key,
                &mut lwe,
                plaintext,
                lwe_noise_distribution,
                &mut encryption_generator,
            );

            let decrypted_plaintext = decrypt_lwe_ciphertext(&lwe_secret_key, &lwe);

            // Round and remove encoding
            // First create a decomposer working on the high 4 bits corresponding to our
            // encoding.
            let decomposer = SignedDecomposer::new(
                DecompositionBaseLog(MSG_BITS as usize),
                DecompositionLevelCount(1),
            );

            let rounded = decomposer.closest_representable(decrypted_plaintext.0);

            // Remove the encoding
            let cleartext = rounded >> ENCODING;

            // Check we recovered the original message
            assert_eq!(cleartext, msg);
        }
    }

}

// fn test_sk_enc_ret_mask_and_noise() {
// 	println!("Testing encrypt_lwe_ciphertext_ret_mask_and_noise");
//     // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
//     // computations
//     // Define parameters for LweCiphertext creation
//     let lwe_dimension = LweDimension(742);
//     let lwe_noise_distribution =
//         DynamicDistribution::new_gaussian_from_std_dev(StandardDev(4.998_277_131_225_527e-11));

//     // Create the PRNG
//     let mut seeder = new_seeder();
//     let seeder = seeder.as_mut();
//     let mut encryption_generator =
//         EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
//     let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

//     const MSG_BITS: u32 = 4;

//     for _ in 0..NB_TESTS {
//         for msg in 0..2u128.pow(MSG_BITS) {
//             // Create the LweSecretKey
//             let lwe_secret_key = allocate_and_generate_new_binary_lwe_secret_key(
//                 lwe_dimension,
//                 &mut secret_generator,
//             );

//             // Create the plaintext
//             const ENCODING: u32 = u128::BITS - MSG_BITS;
//             let plaintext = Plaintext(msg << ENCODING);

//             // Create a new LweCiphertext
//             let mut lwe = LweCiphertext::new(
//                 0u128,
//                 lwe_dimension.to_lwe_size(),
//                 CiphertextModulus::new_native(),
//             );

//             let SecretKeyRandomVectors {
//             	mask,
//             	noise
//             } = encrypt_lwe_ciphertext_ret_mask_and_noise(
//                 &lwe_secret_key,
//                 &mut lwe,
//                 plaintext,
//                 lwe_noise_distribution,
//                 &mut encryption_generator,
//             );
//             println!("Encryption mask: {mask}");
//             println!("Encryption noise: {noise}");

//             let decrypted_plaintext = decrypt_lwe_ciphertext(&lwe_secret_key, &lwe);

//             // Round and remove encoding
//             // First create a decomposer working on the high 4 bits corresponding to our
//             // encoding.
//             let decomposer = SignedDecomposer::new(
//                 DecompositionBaseLog(MSG_BITS as usize),
//                 DecompositionLevelCount(1),
//             );

//             let rounded = decomposer.closest_representable(decrypted_plaintext.0);

//             // Remove the encoding
//             let cleartext = rounded >> ENCODING;

//             // Check we recovered the original message
//             assert_eq!(cleartext, msg);
//         }
//     }

// }

fn test_pk_enc() {
	println!("Testing encrypt_lwe_ciphertext_with_public_key");

	// DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
	// computations
	// Define parameters for LweCiphertext creation
	let lwe_dimension = LweDimension(742);
	let lwe_noise_distribution =
	    Gaussian::from_dispersion_parameter(StandardDev(0.000007069849454709433), 0.0);
	let zero_encryption_count =
	    LwePublicKeyZeroEncryptionCount(lwe_dimension.to_lwe_size().0 * 64 + 128);
	let ciphertext_modulus = CiphertextModulus::new_native();

	// Create the PRNG
	let mut seeder = new_seeder();
	let seeder = seeder.as_mut();
	let mut encryption_generator =
	    EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
	let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

	// Create the LweSecretKey
	let lwe_secret_key =
	    allocate_and_generate_new_binary_lwe_secret_key(lwe_dimension, &mut secret_generator);

	let lwe_public_key = allocate_and_generate_new_lwe_public_key(
	    &lwe_secret_key,
	    zero_encryption_count,
	    lwe_noise_distribution,
	    ciphertext_modulus,
	    &mut encryption_generator,
	);

	// Create the plaintext
	let msg = 3u64;
	let plaintext = Plaintext(msg << 60);

	// Create a new LweCiphertext
	let mut lwe = LweCiphertext::new(0u64, lwe_dimension.to_lwe_size(), ciphertext_modulus);

	encrypt_lwe_ciphertext_with_public_key(
	    &lwe_public_key,
	    &mut lwe,
	    plaintext,
	    &mut secret_generator,
	);

	let decrypted_plaintext = decrypt_lwe_ciphertext(&lwe_secret_key, &lwe);

	// Round and remove encoding
	// First create a decomposer working on the high 4 bits corresponding to our encoding.
	let decomposer = SignedDecomposer::new(DecompositionBaseLog(4), DecompositionLevelCount(1));

	let rounded = decomposer.closest_representable(decrypted_plaintext.0);

	// Remove the encoding
	let cleartext = rounded >> 60;

	// Check we recovered the original message
	assert_eq!(cleartext, msg);

}

fn test_pk_enc_ret_mask() {
	println!("Testing encrypt_lwe_ciphertext_with_public_key_ret_mask");

	// DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
	// computations
	// Define parameters for LweCiphertext creation
	let lwe_dimension = LweDimension(742);
	let lwe_noise_distribution =
	    Gaussian::from_dispersion_parameter(StandardDev(0.000007069849454709433), 0.0);
	let zero_encryption_count =
	    LwePublicKeyZeroEncryptionCount(lwe_dimension.to_lwe_size().0 * 64 + 128);
	let ciphertext_modulus = CiphertextModulus::new_native();

	// Create the PRNG
	let mut seeder = new_seeder();
	let seeder = seeder.as_mut();
	let mut encryption_generator =
	    EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
	let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

	// Create the LweSecretKey
	let lwe_secret_key =
	    allocate_and_generate_new_binary_lwe_secret_key(lwe_dimension, &mut secret_generator);

	let lwe_public_key = allocate_and_generate_new_lwe_public_key(
	    &lwe_secret_key,
	    zero_encryption_count,
	    lwe_noise_distribution,
	    ciphertext_modulus,
	    &mut encryption_generator,
	);

	// Create the plaintext
	let msg = 3u64;
	let plaintext = Plaintext(msg << 60);

	// Create a new LweCiphertext
	let mut lwe = LweCiphertext::new(0u64, lwe_dimension.to_lwe_size(), ciphertext_modulus);

	let PublicKeyRandomVectors {binary_random_vector} = encrypt_lwe_ciphertext_with_public_key_ret_mask(
	    &lwe_public_key,
	    &mut lwe,
	    plaintext,
	    &mut secret_generator,
	);
	// println!("check");
	println!("binary_random_vector length: {:?}", binary_random_vector.len());
	// println!("binary_random_vector: {:?}", binary_random_vector);

	let decrypted_plaintext = decrypt_lwe_ciphertext(&lwe_secret_key, &lwe);

	// Round and remove encoding
	// First create a decomposer working on the high 4 bits corresponding to our encoding.
	let decomposer = SignedDecomposer::new(DecompositionBaseLog(4), DecompositionLevelCount(1));

	let rounded = decomposer.closest_representable(decrypted_plaintext.0);

	// Remove the encoding
	let cleartext = rounded >> 60;

	// Check we recovered the original message
	assert_eq!(cleartext, msg);
	println!("Decryption: correct");

	// deterministically encrypt using the mask in binary_random_vector
	let mut lwe2 = LweCiphertext::new(0u64, lwe_dimension.to_lwe_size(), ciphertext_modulus);
	encrypt_lwe_ciphertext_with_public_key_and_mask(
	    &lwe_public_key,
	    &mut lwe2,
	    plaintext,
	    binary_random_vector,
	);

	assert!(lwe == lwe2);
	println!("Deterministic encryption: correct");

	// println!("check");
	// if lwe != lwe2 {
	// 	println!("lwe != lwe2")
	// }
	// if lwe.clone().into_container() != lwe2.clone().into_container() {
	// 	println!("lwe.into_container() != lwe2.into_container()")
	// }
	// if lwe.clone().ciphertext_modulus() != lwe2.clone().ciphertext_modulus() {
	// 	println!("lwe.ciphertext_modulus() != lwe2.ciphertext_modulus()")
	// }
	// println!("check2");

}

fn test_add() {
	println!("Testing homomorphic addition");

	// DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
	// computations
	// Define parameters for LweCiphertext creation
	let lwe_dimension = LweDimension(742);
	let lwe_noise_distribution =
	    Gaussian::from_dispersion_parameter(StandardDev(0.000007069849454709433), 0.0);
	let zero_encryption_count =
	    LwePublicKeyZeroEncryptionCount(lwe_dimension.to_lwe_size().0 * 64 + 128);
	let ciphertext_modulus = CiphertextModulus::new_native();

	// Create the PRNG
	let mut seeder = new_seeder();
	let seeder = seeder.as_mut();
	let mut encryption_generator =
	    EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
	let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

	// Create the LweSecretKey
	let lwe_secret_key =
	    allocate_and_generate_new_binary_lwe_secret_key(lwe_dimension, &mut secret_generator);

	let lwe_public_key = allocate_and_generate_new_lwe_public_key(
	    &lwe_secret_key,
	    zero_encryption_count,
	    lwe_noise_distribution,
	    ciphertext_modulus,
	    &mut encryption_generator,
	);

	// Create the plaintexts
	let clear_a = 3u64;
	let plaintext_a = Plaintext(clear_a << 60);
	let clear_b = 4u64;
	let plaintext_b = Plaintext(clear_b << 60);

	// Create a new LweCiphertext
	let mut a = LweCiphertext::new(0u64, lwe_dimension.to_lwe_size(), ciphertext_modulus);
	let mut b = LweCiphertext::new(0u64, lwe_dimension.to_lwe_size(), ciphertext_modulus);

	let mask_a = encrypt_lwe_ciphertext_with_public_key_ret_mask(
	    &lwe_public_key,
	    &mut a,
	    plaintext_a,
	    &mut secret_generator,
	);

	let mask_b = encrypt_lwe_ciphertext_with_public_key_ret_mask(
	    &lwe_public_key,
	    &mut b,
	    plaintext_b,
	    &mut secret_generator,
	);
	// println!("check");
	println!("mask_a.binary_random_vector length: {:?}", mask_a.binary_random_vector.len());
	println!("mask_b.binary_random_vector length: {:?}", mask_b.binary_random_vector.len());
	// println!("binary_random_vector: {:?}", binary_random_vector);

	let mut h_c = a.clone();
	lwe_ciphertext_add(&mut h_c, &a, &b);

	let clear_c = clear_a + clear_b;
	let plaintext_c = Plaintext(clear_c << 60);
	// let mut mask_c_vec: Vec<Box<dyn UnsignedTorus>> = Vec::new();
	// let mut mask_c_vec = Vec::<UnsignedTorus>::new();
	// slice_wrapping_add(&mut mask_c_vec, &mask_a.binary_random_vector, &mask_b.binary_random_vector);
	let mask_c_vec = mask_a.binary_random_vector.into_iter().zip(mask_b.binary_random_vector.into_iter())
						.map(|(a, b)| a + b)
						.collect();
	// let mask_c = PublicKeyRandomVectors {
	// 	binary_random_vector: mask_c_vec,
	// };

	// deterministically encrypt using the mask in binary_random_vector
	let mut c = LweCiphertext::new(0u64, lwe_dimension.to_lwe_size(), ciphertext_modulus);
	encrypt_lwe_ciphertext_with_public_key_and_mask(
	    &lwe_public_key,
	    &mut c,
	    plaintext_c,
	    mask_c_vec,
	    // mask_c.binary_random_vector,
	);

	assert!(c == h_c);
	println!("Randomness in homomorphic addition: correct");

	let decrypted_plaintext = decrypt_lwe_ciphertext(&lwe_secret_key, &h_c);

	// Round and remove encoding
	// First create a decomposer working on the high 4 bits corresponding to our encoding.
	let decomposer = SignedDecomposer::new(DecompositionBaseLog(4), DecompositionLevelCount(1));

	let rounded = decomposer.closest_representable(decrypted_plaintext.0);

	// Remove the encoding
	let cleartext = rounded >> 60;

	// Check we recovered the original message
	assert_eq!(cleartext, clear_c);
	println!("Decryption of homomorphic addition: correct");

}

fn main() {
    for argument in std::env::args() {
        if argument == "sk_enc" {
            println!("Testing encrypt_lwe_ciphertext");
            test_sk_enc();
            println!();
        }
        // if argument == "sk_enc2" {
        //     println!("Testing encrypt_lwe_ciphertext_ret_mask_and_noise");
        //     test_sk_enc_ret_mask_and_noise();
        //     println!();
        // }
        if argument == "pk_enc" {
            println!("Testing encrypt_lwe_ciphertext_with_public_key");
            test_pk_enc();
            println!();
        }
        if argument == "pk_enc2" {
            println!("Testing encrypt_lwe_ciphertext_with_public_key_ret_mask");
            test_pk_enc_ret_mask();
            println!();
        }
        if argument == "pk_enc3" {
            println!("Testing hommorphic addition");
            test_add();
            println!();
        }

    }
}
