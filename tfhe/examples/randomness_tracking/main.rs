#![allow(unused_imports)]

// use super::*;
// use crate::core_crypto::commons::generators::DeterministicSeeder;
// #[cfg(feature = "zk-pok")]
// use crate::core_crypto::commons::math::random::RandomGenerator;
// use crate::core_crypto::commons::test_tools;
// #[cfg(feature = "zk-pok")]
// use rand::Rng;

// extern crate tfhe;
// extern crate rayon;
// extern crate pulp;
use std::time::Instant;
use tfhe::shortint::ClassicPBSParameters;
use tfhe::ConfigBuilder;
use tfhe::generate_keys;
use tfhe::FheUint8;
use tfhe::prelude::*;

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

use crate::deterministic_encryption::*;
use crate::deterministic_lin_algebra::*;
use crate::utils::*;

const NB_TESTS: usize = 1;
const MSG_BITS: u32 = 4;
// const ENCODING: u32 = u128::BITS - MSG_BITS;
const ENCODING: u32 = u64::BITS - MSG_BITS;

// const BLOCK_PARAMS: ClassicPBSParameters = tfhe::shortint::prelude::PARAM_MESSAGE_2_CARRY_3_KS_PBS;
const BLOCK_PARAMS: ClassicPBSParameters = tfhe::shortint::prelude::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

mod deterministic_encryption;
mod deterministic_lin_algebra;
mod utils;


fn test_sk_lwe_enc() {
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

    for _ in 0..NB_TESTS {
        for msg in 0..2u128.pow(MSG_BITS) {
            // Create the LweSecretKey
            let lwe_secret_key = allocate_and_generate_new_binary_lwe_secret_key(
                lwe_dimension,
                &mut secret_generator,
            );

            // Create the plaintext
            let plaintext = Plaintext(msg << ENCODING);

            // Create a new LweCiphertext
            let mut lwe = LweCiphertext::new(
                0u128,
                lwe_dimension.to_lwe_size(),
                CiphertextModulus::new_native(),
            );

			let now = Instant::now();
            encrypt_lwe_ciphertext(
                &lwe_secret_key,
                &mut lwe,
                plaintext,
                lwe_noise_distribution,
                &mut encryption_generator,
            );
            let sk_en_time = now.elapsed();
            println!("sk_enc_time: {:?}", sk_en_time);

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

fn test_sk_lwe_enc_det() {
	println!("Testing encrypt_lwe_ciphertext_ret_noise");
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

    for _ in 0..NB_TESTS {
        for msg in 0..2u128.pow(MSG_BITS) {
            // Create the LweSecretKey
            let lwe_secret_key = allocate_and_generate_new_binary_lwe_secret_key(
                lwe_dimension,
                &mut secret_generator,
            );

            // Create the plaintext
            let plaintext = Plaintext(msg << ENCODING);

            // Create a new LweCiphertext
            let mut lwe = LweCiphertext::new(
                0u128,
                lwe_dimension.to_lwe_size(),
                CiphertextModulus::new_native(),
            );

            // let SecretKeyRandomVectors {
            // 	mask,
            // 	noise
            // } = encrypt_lwe_ciphertext_ret_noise(
            let noise = encrypt_lwe_ciphertext_ret_noise(
                &lwe_secret_key,
                &mut lwe,
                plaintext,
                lwe_noise_distribution,
                &mut encryption_generator,
            );
            let mut mask = LweMask::from_container(
	            vec![
	                0u128; 
	                lwe.lwe_size().to_lwe_dimension().0
	            ], 
	            CiphertextModulus::new_native());
	        mask.as_mut().copy_from_slice(lwe.get_mask().as_ref());
            // let mask = lwe.get_mask();
            // println!("Encryption mask: {mask:?}");
            // println!("Encryption noise: {noise:?}");

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

			// deterministically encrypt using the mask in binary_random_vector
            let mut lwe2 = LweCiphertext::new(
                0u128,
                lwe_dimension.to_lwe_size(),
                CiphertextModulus::new_native(),
            );
            encrypt_lwe_ciphertext_deterministic(
                &lwe_secret_key,
                &mut lwe2,
                plaintext,
                lwe_noise_distribution,
                &mut encryption_generator,
                &mask,
                &noise,
            );

			assert!(lwe == lwe2);
			println!("Deterministic LWE encryption: correct");

        }
    }

}

fn test_sk_lwe_add() {
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

    for _ in 0..NB_TESTS {
        for msg in 0..2u128.pow(MSG_BITS) {
     	   for msg2 in 0..2u128.pow(MSG_BITS) {
	            // Create the LweSecretKey
	            let lwe_secret_key = allocate_and_generate_new_binary_lwe_secret_key(
	                lwe_dimension,
	                &mut secret_generator,
	            );

	            // Create the plaintext
	           	let clear_a : u128 = msg;
	           	let clear_b : u128 = msg2;
	           	// let clear_b : u128 = msg+1;
	            let plaintext_a = Plaintext(clear_a << ENCODING);
	            let plaintext_b = Plaintext(clear_b << ENCODING);

	            // Create a new LweCiphertext
	            let mut a = LweCiphertext::new(
	                0u128,
	                lwe_dimension.to_lwe_size(),
	                CiphertextModulus::new_native(),
	            );
	            let mut b = LweCiphertext::new(
	                0u128,
	                lwe_dimension.to_lwe_size(),
	                CiphertextModulus::new_native(),
	            );

	            let noise_a = encrypt_lwe_ciphertext_ret_noise(
	                &lwe_secret_key,
	                &mut a,
	                plaintext_a,
	                lwe_noise_distribution,
	                &mut encryption_generator,
	            );
	            let mask_a = a.get_mask();

	            let noise_b = encrypt_lwe_ciphertext_ret_noise(
	                &lwe_secret_key,
	                &mut b,
	                plaintext_b,
	                lwe_noise_distribution,
	                &mut encryption_generator,
	            );
	            let mask_b = b.get_mask();

				let mut h_c = a.clone();
				lwe_ciphertext_add(&mut h_c, &a, &b);

				// let clear_c = clear_a + clear_b;
				let clear_c : u128 = (clear_a + clear_b) % 2u128.pow(MSG_BITS);
				let plaintext_c = Plaintext(clear_c << ENCODING);
				// deterministically encrypt using the mask in binary_random_vector
	            let mut c = LweCiphertext::new(
	                0u128,
	                lwe_dimension.to_lwe_size(),
	                CiphertextModulus::new_native(),
	            );

				let mut c_clone = c.clone();
				let mut mask_c = c_clone.get_mut_mask();
				lwe_ciphertext_add_mask(&mut mask_c, &mask_a, &mask_b);
				let noise_c = lwe_ciphertext_add_noise(&noise_a, &noise_b);

	            encrypt_lwe_ciphertext_deterministic(
	                &lwe_secret_key,
	                &mut c,
	                plaintext_c,
	                lwe_noise_distribution,
	                &mut encryption_generator,
	                &LweMask::from_container(mask_c.as_ref().to_vec(), mask_c.ciphertext_modulus()),
	                &noise_c,
	            );

				assert!(c == h_c);
				println!("Randomness in LWE homomorphic addition: correct");

	            let decrypted_plaintext = decrypt_lwe_ciphertext(&lwe_secret_key, &h_c);

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
	            assert_eq!(cleartext, clear_c);
				println!("Decryption of homomorphic addition: correct");

        	}
        }
    }
}

fn test_sk_lwe_mult_const() {
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

    for _ in 0..NB_TESTS {
        for msg in 0..2u128.pow(MSG_BITS) {
     	   for msg2 in 0..2u128.pow(MSG_BITS) {
	            // Create the LweSecretKey
	            let lwe_secret_key = allocate_and_generate_new_binary_lwe_secret_key(
	                lwe_dimension,
	                &mut secret_generator,
	            );

	            // Create the plaintext
	           	let clear_a : u128 = msg;
	           	let clear_b : u128 = msg2;
	           	// let clear_b : u128 = msg+1;
	            let plaintext_a = Plaintext(clear_a << ENCODING);

	            // Create a new LweCiphertext
	            let mut a = LweCiphertext::new(
	                0u128,
	                lwe_dimension.to_lwe_size(),
	                CiphertextModulus::new_native(),
	            );

	            let noise_a = encrypt_lwe_ciphertext_ret_noise(
	                &lwe_secret_key,
	                &mut a,
	                plaintext_a,
	                lwe_noise_distribution,
	                &mut encryption_generator,
	            );
	            let mask_a = a.get_mask();

				let mut h_c = a.clone();
				lwe_ciphertext_cleartext_mul(&mut h_c, &a, Cleartext(clear_b));

				// let clear_c = clear_a + clear_b;
				let clear_c : u128 = (clear_a * clear_b) % 2u128.pow(MSG_BITS);
				let plaintext_c = Plaintext(clear_c << ENCODING);
				// deterministically encrypt using the mask in binary_random_vector
	            let mut c = LweCiphertext::new(
	                0u128,
	                lwe_dimension.to_lwe_size(),
	                CiphertextModulus::new_native(),
	            );

				let mut c_clone = c.clone();
				let mut mask_c = c_clone.get_mut_mask();
				lwe_ciphertext_cleartext_mul_mask(&mut mask_c, &mask_a, &clear_b);
				let noise_c = lwe_ciphertext_cleartext_mul_noise(&noise_a, &clear_b);

	            encrypt_lwe_ciphertext_deterministic(
	                &lwe_secret_key,
	                &mut c,
	                plaintext_c,
	                lwe_noise_distribution,
	                &mut encryption_generator,
	                &LweMask::from_container(mask_c.as_ref().to_vec(), mask_c.ciphertext_modulus()),
	                &noise_c,
	            );

				assert!(c == h_c);
				println!("Randomness in homomorphic multiplication with constant: correct");

	            let decrypted_plaintext = decrypt_lwe_ciphertext(&lwe_secret_key, &h_c);

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
	            assert_eq!(cleartext, clear_c);
				println!("Decryption of homomorphic multiplication with constant: correct");

        	}
        }
    }
}

fn test_pk_lwe_enc() {
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

	let now = Instant::now();
	encrypt_lwe_ciphertext_with_public_key(
	    &lwe_public_key,
	    &mut lwe,
	    plaintext,
	    &mut secret_generator,
	);
    let pk_en_time = now.elapsed();
    println!("pk_enc_time: {:?}", pk_en_time);

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

fn test_pk_lwe_enc_det() {
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
	encrypt_lwe_ciphertext_with_public_key_deterministic(
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

fn test_pk_lwe_add() {
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

	// let now = Instant::now();
	let lwe_public_key = allocate_and_generate_new_lwe_public_key(
	    &lwe_secret_key,
	    zero_encryption_count,
	    lwe_noise_distribution,
	    ciphertext_modulus,
	    &mut encryption_generator,
	);
	// let pk_time = now.elapsed();
	// println!("time to generate pk: {:.2?}", pk_time);

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

	let mut mask_c = mask_a.clone();
	println!("mask_c.binary_random_vector length: {:?}", mask_c.binary_random_vector.len());
	lwe_ciphertext_add_pk_random_vectors(&mut mask_c, &mask_a, &mask_b);

	let clear_c = clear_a + clear_b;
	let plaintext_c = Plaintext(clear_c << 60);
	// deterministically encrypt using the mask in binary_random_vector
	let mut c = LweCiphertext::new(0u64, lwe_dimension.to_lwe_size(), ciphertext_modulus);
	encrypt_lwe_ciphertext_with_public_key_deterministic(
	    &lwe_public_key,
	    &mut c,
	    plaintext_c,
	    // mask_c_vec,
	    mask_c.binary_random_vector,
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

fn test_pk_lwe_mult_const() {
	// DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
	// computations
	// Define parameters for LweCiphertext creation
	let lwe_dimension = LweDimension(742);
	let lwe_noise_distribution =
	    Gaussian::from_dispersion_parameter(StandardDev(0.000007069849454709433), 0.0);
	let zero_encryption_count =
	    LwePublicKeyZeroEncryptionCount(lwe_dimension.to_lwe_size().0 * 64 + 128);
	let ciphertext_modulus = CiphertextModulus::new_native();
	println!("ciphertext_modulus: {:?}", ciphertext_modulus);

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

	// Create a new LweCiphertext
	let mut a = LweCiphertext::new(0u64, lwe_dimension.to_lwe_size(), ciphertext_modulus);

	let mask_a = encrypt_lwe_ciphertext_with_public_key_ret_mask(
	    &lwe_public_key,
	    &mut a,
	    plaintext_a,
	    &mut secret_generator,
	);

	// println!("check");
	println!("mask_a.binary_random_vector length: {:?}", mask_a.binary_random_vector.len());
	// println!("binary_random_vector: {:?}", binary_random_vector);

	let mut h_c = a.clone();
	lwe_ciphertext_cleartext_mul(&mut h_c, &a, Cleartext(clear_b));

	let mut mask_c = mask_a.clone();
	println!("mask_c.binary_random_vector length: {:?}", mask_c.binary_random_vector.len());
	lwe_ciphertext_cleartext_mul_pk_random_vectors(&mut mask_c, &mask_a, Cleartext(clear_b));

	let clear_c = clear_a * clear_b;
	let plaintext_c = Plaintext(clear_c << 60);
	// deterministically encrypt using the mask in binary_random_vector
	let mut c = LweCiphertext::new(0u64, lwe_dimension.to_lwe_size(), ciphertext_modulus);
	encrypt_lwe_ciphertext_with_public_key_deterministic(
	    &lwe_public_key,
	    &mut c,
	    plaintext_c,
	    // mask_c_vec,
	    mask_c.binary_random_vector,
	);

	assert!(c == h_c);
	println!("Randomness in homomorphic multiplication with constant: correct");

	let decrypted_plaintext = decrypt_lwe_ciphertext(&lwe_secret_key, &h_c);

	// Round and remove encoding
	// First create a decomposer working on the high 4 bits corresponding to our encoding.
	let decomposer = SignedDecomposer::new(DecompositionBaseLog(4), DecompositionLevelCount(1));

	let rounded = decomposer.closest_representable(decrypted_plaintext.0);

	// Remove the encoding
	let cleartext = rounded >> 60;

	// Check we recovered the original message
	assert_eq!(cleartext, clear_c);
	println!("Decryption of homomorphic multiplication with constant: correct");

}


fn test_sk_glwe_enc() {
	// DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
	// computations
	// Define parameters for GlweCiphertext creation
	let glwe_size = GlweSize(2);
	let polynomial_size = PolynomialSize(1024);
	let glwe_noise_distribution =
	    Gaussian::from_dispersion_parameter(StandardDev(0.00000000000000029403601535432533), 0.0);
	let ciphertext_modulus = CiphertextModulus::new_native();

	// Create the PRNG
	let mut seeder = new_seeder();
	let seeder = seeder.as_mut();
	let mut encryption_generator =
	    EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
	let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

	// Create the GlweSecretKey
	let glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
	    glwe_size.to_glwe_dimension(),
	    polynomial_size,
	    &mut secret_generator,
	);

	// Create the plaintext
	let msg = 3u64;
	let encoded_msg = msg << 60;
	let plaintext_list = PlaintextList::new(encoded_msg, PlaintextCount(polynomial_size.0));

	// Create a new GlweCiphertext
	let mut glwe = GlweCiphertext::new(0u64, glwe_size, polynomial_size, ciphertext_modulus);

	encrypt_glwe_ciphertext(
	    &glwe_secret_key,
	    &mut glwe,
	    &plaintext_list,
	    glwe_noise_distribution,
	    &mut encryption_generator,
	);

	let mut output_plaintext_list = PlaintextList::new(0u64, plaintext_list.plaintext_count());

	decrypt_glwe_ciphertext(&glwe_secret_key, &glwe, &mut output_plaintext_list);

	// Round and remove encoding
	// First create a decomposer working on the high 4 bits corresponding to our encoding.
	let decomposer = SignedDecomposer::new(DecompositionBaseLog(4), DecompositionLevelCount(1));

	output_plaintext_list
	    .iter_mut()
	    .for_each(|elt| *elt.0 = decomposer.closest_representable(*elt.0));

	// Get the raw vector
	let mut cleartext_list = output_plaintext_list.into_container();
	// Remove the encoding
	cleartext_list.iter_mut().for_each(|elt| *elt >>= 60);
	// Get the list immutably
	let cleartext_list = cleartext_list;

	// Check we recovered the original message for each plaintext we encrypted
	cleartext_list.iter().for_each(|&elt| assert_eq!(elt, msg));
}

fn test_sk_glwe_enc_det() {
	// DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
	// computations
	// Define parameters for GlweCiphertext creation
	let glwe_size = GlweSize(2);
	let polynomial_size = PolynomialSize(1024);
	let glwe_noise_distribution =
	    Gaussian::from_dispersion_parameter(StandardDev(0.00000000000000029403601535432533), 0.0);
	let ciphertext_modulus = CiphertextModulus::new_native();

	// Create the PRNG
	let mut seeder = new_seeder();
	let seeder = seeder.as_mut();
	let mut encryption_generator =
	    EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
	let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

	// Create the GlweSecretKey
	let glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
	    glwe_size.to_glwe_dimension(),
	    polynomial_size,
	    &mut secret_generator,
	);

	// Create the plaintext
	let msg = 3u64;
	let encoded_msg = msg << 60;
	let plaintext_list = PlaintextList::new(encoded_msg, PlaintextCount(polynomial_size.0));

	// Create a new GlweCiphertext
	let mut glwe = GlweCiphertext::new(0u64, glwe_size, polynomial_size, ciphertext_modulus);

	let noise = encrypt_glwe_ciphertext_ret_noise(
	    &glwe_secret_key,
	    &mut glwe,
	    &plaintext_list,
	    glwe_noise_distribution,
	    &mut encryption_generator,
	);
	let mask = glwe.get_mask();

	let mut output_plaintext_list = PlaintextList::new(0u64, plaintext_list.plaintext_count());

	decrypt_glwe_ciphertext(&glwe_secret_key, &glwe, &mut output_plaintext_list);

	// Round and remove encoding
	// First create a decomposer working on the high 4 bits corresponding to our encoding.
	let decomposer = SignedDecomposer::new(DecompositionBaseLog(4), DecompositionLevelCount(1));

	output_plaintext_list
	    .iter_mut()
	    .for_each(|elt| *elt.0 = decomposer.closest_representable(*elt.0));

	// Get the raw vector
	let mut cleartext_list = output_plaintext_list.into_container();
	// Remove the encoding
	cleartext_list.iter_mut().for_each(|elt| *elt >>= 60);
	// Get the list immutably
	let cleartext_list = cleartext_list;

	// Check we recovered the original message for each plaintext we encrypted
	cleartext_list.iter().for_each(|&elt| assert_eq!(elt, msg));

	let mut glwe2 = GlweCiphertext::new(0u64, glwe_size, polynomial_size, ciphertext_modulus);
	encrypt_glwe_ciphertext_deterministic(
	    &glwe_secret_key,
	    &mut glwe2,
	    &plaintext_list,
	    glwe_noise_distribution,
	    &mut encryption_generator,
	    &mask,
	    &noise,
	);

	assert!(glwe == glwe2);
	println!("Deterministic GLWE encryption: correct");

}

fn test_sk_glwe_add() {
	// DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
	// computations
	// Define parameters for GlweCiphertext creation
	let glwe_dimension = GlweDimension(1);
	let polynomial_size = PolynomialSize(2048);
	let glwe_noise_distribution =
	    Gaussian::from_dispersion_parameter(StandardDev(0.00000000000000029403601535432533), 0.0);
	let ciphertext_modulus = CiphertextModulus::new_native();

	// Create the PRNG
	let mut seeder = new_seeder();
	let seeder = seeder.as_mut();
	let mut encryption_generator =
	    EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
	let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

	// Create the GlweSecretKey
	let glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
	    glwe_dimension,
	    polynomial_size,
	    &mut secret_generator,
	);

    for _ in 0..NB_TESTS {
        for msg in 0..2u128.pow(MSG_BITS) {
     	   for msg2 in 0..2u128.pow(MSG_BITS) {
				// Create the plaintext
				let clear_a : u128 = msg;
				let clear_b :u128 = msg2;
				let encoded_clear_a = clear_a << ENCODING;
				let encoded_clear_b = clear_b << ENCODING;
				let plaintext_list_a = PlaintextList::new(encoded_clear_a, PlaintextCount(polynomial_size.0));
				let plaintext_list_b = PlaintextList::new(encoded_clear_b, PlaintextCount(polynomial_size.0));

				// Create a new GlweCiphertext
				let mut a = GlweCiphertext::new(
				    0u128,
				    glwe_dimension.to_glwe_size(),
				    polynomial_size,
				    ciphertext_modulus,
				);
				let noise_a = encrypt_glwe_ciphertext_ret_noise(
				    &glwe_secret_key,
				    &mut a,
				    &plaintext_list_a,
				    glwe_noise_distribution,
				    &mut encryption_generator,
				);
	            let mask_a = a.get_mask();

				let mut b = GlweCiphertext::new(
				    0u128,
				    glwe_dimension.to_glwe_size(),
				    polynomial_size,
				    ciphertext_modulus,
				);
				let noise_b = encrypt_glwe_ciphertext_ret_noise(
				    &glwe_secret_key,
				    &mut b,
				    &plaintext_list_b,
				    glwe_noise_distribution,
				    &mut encryption_generator,
				);
	            let mask_b = b.get_mask();

				let mut h_c = a.clone();

				glwe_ciphertext_add(&mut h_c, &a, &b);

				// TESTING: deterministic homomorphic addition
				let clear_c : u128 = (clear_a + clear_b) % 2u128.pow(MSG_BITS);
				let encoded_clear_c = clear_c << ENCODING;
				let plaintext_list_c = PlaintextList::new(encoded_clear_c, PlaintextCount(polynomial_size.0));
				
				let mut c = GlweCiphertext::new(
				    0u128,
				    glwe_dimension.to_glwe_size(),
				    polynomial_size,
				    ciphertext_modulus,
				);

				let mut c_clone = c.clone();
				let mut mask_c = c_clone.get_mut_mask();
				glwe_ciphertext_add_mask(&mut mask_c, &mask_a, &mask_b);
				let noise_c = glwe_ciphertext_add_noise(&noise_a, &noise_b);

				encrypt_glwe_ciphertext_deterministic(
				    &glwe_secret_key,
				    &mut c,
				    &plaintext_list_c,
				    glwe_noise_distribution,
				    &mut encryption_generator,
	                &GlweMask::from_container(mask_c.as_ref(), mask_c.polynomial_size(), mask_c.ciphertext_modulus()),
				    // &mask,
				    &noise_c,
				);

				assert!(c == h_c);
				println!("Randomness in GLWE homomorphic addition: correct");

				// TESTING: decryption
				let mut plaintext_list_c =
				    PlaintextList::new(0u128, PlaintextCount(h_c.polynomial_size().0));

				decrypt_glwe_ciphertext(&glwe_secret_key, &h_c, &mut plaintext_list_c);

				// Round and remove encoding
				// First create a decomposer working on the high 4 bits corresponding to our encoding.
				let decomposer = SignedDecomposer::new(DecompositionBaseLog(4), DecompositionLevelCount(1));

				// Round and remove encoding in the output plaintext list
				plaintext_list_c
				    .iter_mut()
				    .for_each(|x| *x.0 = decomposer.closest_representable(*x.0) >> ENCODING);

				// Check we recovered the expected result
				assert!(plaintext_list_c.iter().all(|x| *x.0 == clear_c));
			}
		}
	}
}

fn test_sk_glwe_mult_const() {
	// DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
	// computations
	// Define parameters for GlweCiphertext creation
	let glwe_dimension = GlweDimension(1);
	let polynomial_size = PolynomialSize(2048);
	let glwe_noise_distribution =
	    Gaussian::from_dispersion_parameter(StandardDev(0.00000000000000029403601535432533), 0.0);
	let ciphertext_modulus = CiphertextModulus::new_native();

	// Create the PRNG
	let mut seeder = new_seeder();
	let seeder = seeder.as_mut();
	let mut encryption_generator =
	    EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
	let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

	// Create the GlweSecretKey
	let glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
	    glwe_dimension,
	    polynomial_size,
	    &mut secret_generator,
	);

    for _ in 0..NB_TESTS {
        for msg in 0..2u128.pow(MSG_BITS) {
     	   for msg2 in 0..2u128.pow(MSG_BITS) {
				// Create the plaintext
				let clear_a : u128 = msg;
				let clear_b :u128 = msg2;
				let encoded_clear_a = clear_a << ENCODING;
				let plaintext_list_a = PlaintextList::new(encoded_clear_a, PlaintextCount(polynomial_size.0));

				// Create a new GlweCiphertext
				let mut a = GlweCiphertext::new(
				    0u128,
				    glwe_dimension.to_glwe_size(),
				    polynomial_size,
				    ciphertext_modulus,
				);
				let noise_a = encrypt_glwe_ciphertext_ret_noise(
				    &glwe_secret_key,
				    &mut a,
				    &plaintext_list_a,
				    glwe_noise_distribution,
				    &mut encryption_generator,
				);
	            let mask_a = a.get_mask();

				let mut h_c = a.clone();
				glwe_ciphertext_cleartext_mul(&mut h_c, &a, Cleartext(clear_b));

				// TESTING: deterministic homomorphic multiplication with constant 
				let clear_c : u128 = (clear_a * clear_b) % 2u128.pow(MSG_BITS);
				let encoded_clear_c = clear_c << ENCODING;
				let plaintext_list_c = PlaintextList::new(encoded_clear_c, PlaintextCount(polynomial_size.0));
				
				let mut c = GlweCiphertext::new(
				    0u128,
				    glwe_dimension.to_glwe_size(),
				    polynomial_size,
				    ciphertext_modulus,
				);

				let mut c_clone = c.clone();
				let mut mask_c = c_clone.get_mut_mask();
				glwe_ciphertext_cleartext_mul_mask(&mut mask_c, &mask_a, &clear_b);
				let noise_c = glwe_ciphertext_cleartext_mul_noise(&noise_a, &clear_b);

				encrypt_glwe_ciphertext_deterministic(
				    &glwe_secret_key,
				    &mut c,
				    &plaintext_list_c,
				    glwe_noise_distribution,
				    &mut encryption_generator,
	                &GlweMask::from_container(mask_c.as_ref(), mask_c.polynomial_size(), mask_c.ciphertext_modulus()),
				    // &mask,
				    &noise_c,
				);

				assert!(c == h_c);
				println!("Randomness in GLWE homomorphic multiplication with constant: correct");

				// TESTING: decryption
				let mut plaintext_list_c =
				    PlaintextList::new(0u128, PlaintextCount(h_c.polynomial_size().0));

				decrypt_glwe_ciphertext(&glwe_secret_key, &h_c, &mut plaintext_list_c);

				// Round and remove encoding
				// First create a decomposer working on the high 4 bits corresponding to our encoding.
				let decomposer = SignedDecomposer::new(DecompositionBaseLog(4), DecompositionLevelCount(1));

				// Round and remove encoding in the output plaintext list
				plaintext_list_c
				    .iter_mut()
				    .for_each(|x| *x.0 = decomposer.closest_representable(*x.0) >> ENCODING);

				// Check we recovered the expected result
				assert!(plaintext_list_c
				    .iter()
				    .all(|x| *x.0 == clear_c));
			}
		}
	}
}

fn test_sk_ggsw_enc() {
	println!("Testing encrypt_constant_seeded_ggsw_ciphertext");
	use tfhe::core_crypto::prelude::*;

	// DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
	// computations
	// Define parameters for GgswCiphertext creation
	let glwe_size = GlweSize(2);
	let polynomial_size = PolynomialSize(1024);
	let decomp_base_log = DecompositionBaseLog(8);
	let decomp_level_count = DecompositionLevelCount(3);
	let glwe_noise_distribution =
	    Gaussian::from_dispersion_parameter(StandardDev(0.00000000000000029403601535432533), 0.0);
	let ciphertext_modulus = CiphertextModulus::new_native();

	// Create the PRNG
	let mut seeder = new_seeder();
	let seeder = seeder.as_mut();
	let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

	// Create the GlweSecretKey
	let glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
	    glwe_size.to_glwe_dimension(),
	    polynomial_size,
	    &mut secret_generator,
	);

	// Create the cleartext
	let cleartext = Cleartext(3u64);

	// Create a new GgswCiphertext
	let mut ggsw = SeededGgswCiphertext::new(
	    0u64,
	    glwe_size,
	    polynomial_size,
	    decomp_base_log,
	    decomp_level_count,
	    seeder.seed().into(),
	    ciphertext_modulus,
	);

	encrypt_constant_seeded_ggsw_ciphertext(
	    &glwe_secret_key,
	    &mut ggsw,
	    cleartext,
	    glwe_noise_distribution,
	    seeder,
	);

	// println!("ggsw: {:?}", ggsw);
	let ggsw = ggsw.decompress_into_ggsw_ciphertext();
	// println!("ggsw: {:?}", ggsw);

	let decrypted = decrypt_constant_ggsw_ciphertext(&glwe_secret_key, &ggsw);
	assert_eq!(decrypted, cleartext);

}

fn test_sk_ggsw_enc_det() {
	println!("Testing encrypt_constant_seeded_ggsw_ciphertext");
	use tfhe::core_crypto::prelude::*;

	// DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
	// computations
	// Define parameters for GgswCiphertext creation
	let glwe_size = GlweSize(2);
	let polynomial_size = PolynomialSize(1024);
	let decomp_base_log = DecompositionBaseLog(8);
	let decomp_level_count = DecompositionLevelCount(3);
	let glwe_noise_distribution =
	    Gaussian::from_dispersion_parameter(StandardDev(0.00000000000000029403601535432533), 0.0);
	let ciphertext_modulus = CiphertextModulus::new_native();

	// Create the PRNG
	let mut seeder = new_seeder();
	let seeder = seeder.as_mut();
	let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

	// Create the GlweSecretKey
	let glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
	    glwe_size.to_glwe_dimension(),
	    polynomial_size,
	    &mut secret_generator,
	);

	// Create the cleartext
	let cleartext = Cleartext(3u64);

	// Create a new GgswCiphertext
	let ggsw_seed = seeder.seed().into();
	// println!("ggsw_seed: {:?}", ggsw_seed);
	let mut ggsw = SeededGgswCiphertext::new(
	    0u64,
	    glwe_size,
	    polynomial_size,
	    decomp_base_log,
	    decomp_level_count,
	    ggsw_seed,
	    ciphertext_modulus,
	);

	let (mask_vector, noise_vector) = encrypt_constant_seeded_ggsw_ciphertext_ret_mask_and_noise(
	// encrypt_constant_seeded_ggsw_ciphertext_ret_mask_and_noise(
	    &glwe_secret_key,
	    &mut ggsw,
	    cleartext,
	    glwe_noise_distribution,
	    seeder,
	);

	let ggsw = ggsw.decompress_into_ggsw_ciphertext();

	let decrypted = decrypt_constant_ggsw_ciphertext(&glwe_secret_key, &ggsw);
	assert_eq!(decrypted, cleartext);

	// deterministically encrypt using the mask in binary_random_vector
	// let ggsw2_seed = seeder.seed().into(); // this gives a new value, don't use
	// println!("ggsw2_seed: {:?}", ggsw2_seed);
	let mut ggsw2 = SeededGgswCiphertext::new(
	    0u64,
	    glwe_size,
	    polynomial_size,
	    decomp_base_log,
	    decomp_level_count,
	    ggsw_seed, // use the same seed as in ggsw
	    // ggsw2_seed, // this gives a new value, don't use
	    ciphertext_modulus,
	);
	
    encrypt_constant_seeded_ggsw_ciphertext_deterministic(
        &glwe_secret_key,
	    &mut ggsw2,
	    cleartext,
	    glwe_noise_distribution,
	    seeder,
	    &mask_vector,
	    &noise_vector,
	);
	// assert!(ggsw.ggsw_ciphertext_size() == ggsw2.ggsw_ciphertext_size());
	// assert!(ggsw.ggsw_level_matrix_size() == ggsw2.ggsw_level_matrix_size());
	// assert!(ggsw.ggsw_ciphertext_encryption_mask_sample_count() == ggsw2.ggsw_ciphertext_encryption_mask_sample_count());
	// assert!(ggsw.ggsw_level_matrix_encryption_mask_sample_count() == ggsw2.ggsw_level_matrix_encryption_mask_sample_count());
	// assert!(ggsw.ggsw_ciphertext_encryption_noise_sample_count() == ggsw2.ggsw_ciphertext_encryption_noise_sample_count());
	// assert!(ggsw.ggsw_level_matrix_encryption_noise_sample_count() == ggsw2.ggsw_level_matrix_encryption_noise_sample_count());
	
	// assert!(ggsw.glwe_size() == ggsw2.glwe_size());
	// assert!(ggsw.polynomial_size() == ggsw2.polynomial_size());
	// assert!(ggsw.decomposition_base_log() == ggsw2.decomposition_base_log());
	// assert!(ggsw.ciphertext_modulus() == ggsw2.ciphertext_modulus());
	// if (ggsw.as_view() != ggsw2.as_view()) {
	// 	println!("FAILED: as_view");
	// 	println!("ggsw.as_view() : {:?}", ggsw.as_view());
	// 	println!("ggsw2.as_view(): {:?}", ggsw2.as_view());

	// }
	// if (ggsw.as_ref() != ggsw2.as_ref()) {
	// 	println!("FAILED: as_ref");
	// }	
	// if (ggsw.as_polynomial_list() != ggsw2.as_polynomial_list()) {
	// 	println!("FAILED: as_polynomial_list");
	// }	
	// if (ggsw.as_glwe_list() != ggsw2.as_glwe_list()) {
	// 	println!("FAILED: as_glwe_list");
	// }

	// println!("ggsw : {:?}", ggsw);
	// println!("ggsw2: {:?}", ggsw2);
	// assert!(ggsw == ggsw2);

	let ggsw2 = ggsw2.decompress_into_ggsw_ciphertext();
	assert!(ggsw == ggsw2);
	println!("Deterministic GGSW encryption: correct");


}

fn test_sk_ggsw_par_enc() {
	// DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
	// computations
	// Define parameters for GgswCiphertext creation
	let glwe_size = GlweSize(2);
	let polynomial_size = PolynomialSize(1024);
	let decomp_base_log = DecompositionBaseLog(8);
	let decomp_level_count = DecompositionLevelCount(3);
	let glwe_noise_distribution =
	    Gaussian::from_dispersion_parameter(StandardDev(0.00000000000000029403601535432533), 0.0);
	let ciphertext_modulus = CiphertextModulus::new_native();

	// Create the PRNG
	let mut seeder = new_seeder();
	let seeder = seeder.as_mut();
	let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

	// Create the GlweSecretKey
	let glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
	    glwe_size.to_glwe_dimension(),
	    polynomial_size,
	    &mut secret_generator,
	);

	// Create the cleartext
	let cleartext = Cleartext(3u64);

	// Create a new GgswCiphertext
	let mut ggsw = SeededGgswCiphertext::new(
	    0u64,
	    glwe_size,
	    polynomial_size,
	    decomp_base_log,
	    decomp_level_count,
	    seeder.seed().into(),
	    ciphertext_modulus,
	);

	par_encrypt_constant_seeded_ggsw_ciphertext(
	    &glwe_secret_key,
	    &mut ggsw,
	    cleartext,
	    glwe_noise_distribution,
	    seeder,
	);

	let ggsw = ggsw.decompress_into_ggsw_ciphertext();

	let decrypted = decrypt_constant_ggsw_ciphertext(&glwe_secret_key, &ggsw);
	assert_eq!(decrypted, cleartext);
}

fn test_sk_ggsw_par_enc_det() {
	// DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
	// computations
	// Define parameters for GgswCiphertext creation
	let glwe_size = GlweSize(2);
	let polynomial_size = PolynomialSize(1024);
	let decomp_base_log = DecompositionBaseLog(8);
	let decomp_level_count = DecompositionLevelCount(3);
	let glwe_noise_distribution =
	    Gaussian::from_dispersion_parameter(StandardDev(0.00000000000000029403601535432533), 0.0);
	let ciphertext_modulus = CiphertextModulus::new_native();

	// Create the PRNG
	let mut seeder = new_seeder();
	let seeder = seeder.as_mut();
	let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

	// Create the GlweSecretKey
	let glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
	    glwe_size.to_glwe_dimension(),
	    polynomial_size,
	    &mut secret_generator,
	);

	// Create the cleartext
	let cleartext = Cleartext(3u64);

	// Create a new GgswCiphertext
	let ggsw_seed = seeder.seed().into();
	let mut ggsw = SeededGgswCiphertext::new(
	    0u64,
	    glwe_size,
	    polynomial_size,
	    decomp_base_log,
	    decomp_level_count,
	    ggsw_seed,
	    ciphertext_modulus,
	);

	let (mask_vector, noise_vector) = par_encrypt_constant_seeded_ggsw_ciphertext_ret_mask_and_noise(
	// par_encrypt_constant_seeded_ggsw_ciphertext(
	    &glwe_secret_key,
	    &mut ggsw,
	    cleartext,
	    glwe_noise_distribution,
	    seeder,
	);

	let ggsw = ggsw.decompress_into_ggsw_ciphertext();

	let decrypted = decrypt_constant_ggsw_ciphertext(&glwe_secret_key, &ggsw);
	assert_eq!(decrypted, cleartext);

	// deterministically encrypt using the mask in binary_random_vector
	// let ggsw2_seed = seeder.seed().into(); // this gives a new value, don't use
	// println!("ggsw2_seed: {:?}", ggsw2_seed);
	let mut ggsw2 = SeededGgswCiphertext::new(
	    0u64,
	    glwe_size,
	    polynomial_size,
	    decomp_base_log,
	    decomp_level_count,
	    ggsw_seed, // use the same seed as in ggsw
	    // ggsw2_seed, // this gives a new value, don't use
	    ciphertext_modulus,
	);
	
    par_encrypt_constant_seeded_ggsw_ciphertext_deterministic(
        &glwe_secret_key,
	    &mut ggsw2,
	    cleartext,
	    glwe_noise_distribution,
	    seeder,
	    &mask_vector,
	    &noise_vector,
	);
	// assert!(ggsw.ggsw_ciphertext_size() == ggsw2.ggsw_ciphertext_size());
	// assert!(ggsw.ggsw_level_matrix_size() == ggsw2.ggsw_level_matrix_size());
	// assert!(ggsw.ggsw_ciphertext_encryption_mask_sample_count() == ggsw2.ggsw_ciphertext_encryption_mask_sample_count());
	// assert!(ggsw.ggsw_level_matrix_encryption_mask_sample_count() == ggsw2.ggsw_level_matrix_encryption_mask_sample_count());
	// assert!(ggsw.ggsw_ciphertext_encryption_noise_sample_count() == ggsw2.ggsw_ciphertext_encryption_noise_sample_count());
	// assert!(ggsw.ggsw_level_matrix_encryption_noise_sample_count() == ggsw2.ggsw_level_matrix_encryption_noise_sample_count());
	
	// assert!(ggsw.glwe_size() == ggsw2.glwe_size());
	// assert!(ggsw.polynomial_size() == ggsw2.polynomial_size());
	// assert!(ggsw.decomposition_base_log() == ggsw2.decomposition_base_log());
	// assert!(ggsw.ciphertext_modulus() == ggsw2.ciphertext_modulus());
	// if (ggsw.as_view() != ggsw2.as_view()) {
	// 	println!("FAILED: as_view");
	// 	println!("ggsw.as_view() : {:?}", ggsw.as_view());
	// 	println!("ggsw2.as_view(): {:?}", ggsw2.as_view());

	// }
	// if (ggsw.as_ref() != ggsw2.as_ref()) {
	// 	println!("FAILED: as_ref");
	// }	
	// if (ggsw.as_polynomial_list() != ggsw2.as_polynomial_list()) {
	// 	println!("FAILED: as_polynomial_list");
	// }	
	// if (ggsw.as_glwe_list() != ggsw2.as_glwe_list()) {
	// 	println!("FAILED: as_glwe_list");
	// }

	// println!("ggsw : {:?}", ggsw);
	// println!("ggsw2: {:?}", ggsw2);
	// assert!(ggsw == ggsw2);

	let ggsw2 = ggsw2.decompress_into_ggsw_ciphertext();
	assert!(ggsw == ggsw2);
	println!("Deterministic GGSW parallel encryption: correct");

}

fn test_blind_rotate() {
	// This example recreates a PBS by combining a blind rotate and a sample extract.

	// DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
	// computations
	// Define the parameters for a 4 bits message able to hold the doubled 2 bits message
	let small_lwe_dimension = LweDimension(742);
	let glwe_dimension = GlweDimension(1);
	let polynomial_size = PolynomialSize(2048);
	let lwe_noise_distribution =
	    Gaussian::from_dispersion_parameter(StandardDev(0.000007069849454709433), 0.0);
	let glwe_noise_distribution =
	    Gaussian::from_dispersion_parameter(StandardDev(0.00000000000000029403601535432533), 0.0);
	let pbs_base_log = DecompositionBaseLog(23);
	let pbs_level = DecompositionLevelCount(1);
	let ciphertext_modulus = CiphertextModulus::new_native();

	// Request the best seeder possible, starting with hardware entropy sources and falling back to
	// /dev/random on Unix systems if enabled via cargo features
	let mut boxed_seeder = new_seeder();
	// Get a mutable reference to the seeder as a trait object from the Box returned by new_seeder
	let seeder = boxed_seeder.as_mut();

	// Create a generator which uses a CSPRNG to generate secret keys
	let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

	// Create a generator which uses two CSPRNGs to generate public masks and secret encryption
	// noise
	let mut encryption_generator =
	    EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);

	println!("Generating keys...");

	// Generate an LweSecretKey with binary coefficients
	let small_lwe_sk =
	    LweSecretKey::generate_new_binary(small_lwe_dimension, &mut secret_generator);

	// Generate a GlweSecretKey with binary coefficients
	let glwe_sk =
	    GlweSecretKey::generate_new_binary(glwe_dimension, polynomial_size, &mut secret_generator);

	// Create a copy of the GlweSecretKey re-interpreted as an LweSecretKey
	let big_lwe_sk = glwe_sk.clone().into_lwe_secret_key();

	// Generate the seeded bootstrapping key to show how to handle entity decompression,
	// we use the parallel variant for performance reason
	let std_bootstrapping_key = par_allocate_and_generate_new_seeded_lwe_bootstrap_key(
	    &small_lwe_sk,
	    &glwe_sk,
	    pbs_base_log,
	    pbs_level,
	    glwe_noise_distribution,
	    ciphertext_modulus,
	    seeder,
	);

	// We decompress the bootstrapping key
	let std_bootstrapping_key: LweBootstrapKeyOwned<u64> =
	    std_bootstrapping_key.decompress_into_lwe_bootstrap_key();

	// Create the empty bootstrapping key in the Fourier domain
	let mut fourier_bsk = FourierLweBootstrapKey::new(
	    std_bootstrapping_key.input_lwe_dimension(),
	    std_bootstrapping_key.glwe_size(),
	    std_bootstrapping_key.polynomial_size(),
	    std_bootstrapping_key.decomposition_base_log(),
	    std_bootstrapping_key.decomposition_level_count(),
	);

	// Use the conversion function (a memory optimized version also exists but is more complicated
	// to use) to convert the standard bootstrapping key to the Fourier domain
	convert_standard_lwe_bootstrap_key_to_fourier(&std_bootstrapping_key, &mut fourier_bsk);
	// We don't need the standard bootstrapping key anymore
	drop(std_bootstrapping_key);

	// Our 4 bits message space
	let message_modulus = 1u64 << 4;

	// Our input message
	let input_message = 3u64;

	// Delta used to encode 4 bits of message + a bit of padding on u64
	let delta = (1_u64 << 63) / message_modulus;

	// Apply our encoding
	let plaintext = Plaintext(input_message * delta);

	// Allocate a new LweCiphertext and encrypt our plaintext
	let lwe_ciphertext_in: LweCiphertextOwned<u64> = allocate_and_encrypt_new_lwe_ciphertext(
	    &small_lwe_sk,
	    plaintext,
	    lwe_noise_distribution,
	    ciphertext_modulus,
	    &mut encryption_generator,
	);

	// Now we will use a PBS to compute a multiplication by 2, it is NOT the recommended way of
	// doing this operation in terms of performance as it's much more costly than a multiplication
	// with a cleartext, however it resets the noise in a ciphertext to a nominal level and allows
	// to evaluate arbitrary functions so depending on your use case it can be a better fit.

	// Generate the accumulator for our multiplication by 2 using a simple closure
	let mut accumulator: GlweCiphertextOwned<u64> = generate_programmable_bootstrap_glwe_lut(
	    polynomial_size,
	    glwe_dimension.to_glwe_size(),
	    message_modulus as usize,
	    ciphertext_modulus,
	    delta,
	    |x: u64| 2 * x,
	);

	// Allocate the LweCiphertext to store the result of the PBS
	let mut pbs_multiplication_ct = LweCiphertext::new(
	    0u64,
	    big_lwe_sk.lwe_dimension().to_lwe_size(),
	    ciphertext_modulus,
	);
	println!("Performing blind rotation...");
	blind_rotate_assign(&lwe_ciphertext_in, &mut accumulator, &fourier_bsk);
	println!("Performing sample extraction...");
	extract_lwe_sample_from_glwe_ciphertext(
	    &accumulator,
	    &mut pbs_multiplication_ct,
	    MonomialDegree(0),
	);

	// Decrypt the PBS multiplication result
	let pbs_multiplication_plaintext: Plaintext<u64> =
	    decrypt_lwe_ciphertext(&big_lwe_sk, &pbs_multiplication_ct);

	// Create a SignedDecomposer to perform the rounding of the decrypted plaintext
	// We pass a DecompositionBaseLog of 5 and a DecompositionLevelCount of 1 indicating we want to
	// round the 5 MSB, 1 bit of padding plus our 4 bits of message
	let signed_decomposer =
	    SignedDecomposer::new(DecompositionBaseLog(5), DecompositionLevelCount(1));

	// Round and remove our encoding
	let pbs_multiplication_result: u64 =
	    signed_decomposer.closest_representable(pbs_multiplication_plaintext.0) / delta;

	println!("Checking result...");
	assert_eq!(6, pbs_multiplication_result);
	println!(
	    "Multiplication via PBS result is correct! Expected 6, got {pbs_multiplication_result}"
	);
}

fn test_blind_rotate_det() {
	// This example recreates a PBS by combining a blind rotate and a sample extract.

	// DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
	// computations
	// Define the parameters for a 4 bits message able to hold the doubled 2 bits message
	let small_lwe_dimension = LweDimension(742);
	let glwe_dimension = GlweDimension(1);
	let polynomial_size = PolynomialSize(2048);
	let lwe_noise_distribution =
	    Gaussian::from_dispersion_parameter(StandardDev(0.000007069849454709433), 0.0);
	let glwe_noise_distribution =
	    Gaussian::from_dispersion_parameter(StandardDev(0.00000000000000029403601535432533), 0.0);
	let pbs_base_log = DecompositionBaseLog(23);
	let pbs_level = DecompositionLevelCount(1);
	let ciphertext_modulus = CiphertextModulus::new_native();

	// Request the best seeder possible, starting with hardware entropy sources and falling back to
	// /dev/random on Unix systems if enabled via cargo features
	let mut boxed_seeder = new_seeder();
	// Get a mutable reference to the seeder as a trait object from the Box returned by new_seeder
	let seeder = boxed_seeder.as_mut();

	// Create a generator which uses a CSPRNG to generate secret keys
	let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

	// Create a generator which uses two CSPRNGs to generate public masks and secret encryption
	// noise
	let mut encryption_generator =
	    EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);

	println!("Generating keys...");

	// Generate an LweSecretKey with binary coefficients
	let small_lwe_sk =
	    LweSecretKey::generate_new_binary(small_lwe_dimension, &mut secret_generator);

	// Generate a GlweSecretKey with binary coefficients
	let glwe_sk =
	    GlweSecretKey::generate_new_binary(glwe_dimension, polynomial_size, &mut secret_generator);

	// Create a copy of the GlweSecretKey re-interpreted as an LweSecretKey
	let big_lwe_sk = glwe_sk.clone().into_lwe_secret_key();

	// Generate the seeded bootstrapping key to show how to handle entity decompression,
	// we use the parallel variant for performance reason
	let (std_bootstrapping_key, bsk_mask_vector, bsk_noise_vector) = par_allocate_and_generate_new_seeded_lwe_bootstrap_key_ret_mask_and_noise(
	    &small_lwe_sk,
	    &glwe_sk,
	    pbs_base_log,
	    pbs_level,
	    glwe_noise_distribution,
	    ciphertext_modulus,
	    seeder,
	);

	// We decompress the bootstrapping key
	let std_bootstrapping_key: LweBootstrapKeyOwned<u64> =
	    std_bootstrapping_key.decompress_into_lwe_bootstrap_key();

	// Create the empty bootstrapping key in the Fourier domain
	let mut fourier_bsk = FourierLweBootstrapKey::new(
	    std_bootstrapping_key.input_lwe_dimension(),
	    std_bootstrapping_key.glwe_size(),
	    std_bootstrapping_key.polynomial_size(),
	    std_bootstrapping_key.decomposition_base_log(),
	    std_bootstrapping_key.decomposition_level_count(),
	);

	// Use the conversion function (a memory optimized version also exists but is more complicated
	// to use) to convert the standard bootstrapping key to the Fourier domain
	// TODO: does this affect bsk_mask_vector and bsk_mask_error? Hopefully not.
	convert_standard_lwe_bootstrap_key_to_fourier(&std_bootstrapping_key, &mut fourier_bsk);
	// We don't need the standard bootstrapping key anymore
	drop(std_bootstrapping_key);

	// Our 4 bits message space
	let message_modulus = 1u64 << 4;

	// Our input message
	let input_message = 3u64;

	// Delta used to encode 4 bits of message + a bit of padding on u64
	let delta = (1_u64 << 63) / message_modulus;

	// Apply our encoding
	let plaintext = Plaintext(input_message * delta);

	// Allocate a new LweCiphertext and encrypt our plaintext
	let (lwe_ciphertext_in, lwe_ciphertext_in_noise) : (LweCiphertextOwned<u64>, LweBody<u64>) = allocate_and_encrypt_new_lwe_ciphertext_ret_noise(
	    &small_lwe_sk,
	    plaintext,
	    lwe_noise_distribution,
	    ciphertext_modulus,
	    &mut encryption_generator,
	);
	let lwe_ciphertext_in_mask = lwe_ciphertext_in.get_mask();

	// Now we will use a PBS to compute a multiplication by 2, it is NOT the recommended way of
	// doing this operation in terms of performance as it's much more costly than a multiplication
	// with a cleartext, however it resets the noise in a ciphertext to a nominal level and allows
	// to evaluate arbitrary functions so depending on your use case it can be a better fit.

	// Generate the accumulator for our multiplication by 2 using a simple closure
	let mut accumulator: GlweCiphertextOwned<u64> = generate_programmable_bootstrap_glwe_lut(
	    polynomial_size,
	    glwe_dimension.to_glwe_size(),
	    message_modulus as usize,
	    ciphertext_modulus,
	    delta,
	    |x: u64| 2 * x,
	);
	// accumulator_mask and accumulator_noise are zero.
	let _accumulator_mask = accumulator.get_mask();
	let _accumulator_noise = GlweBody::<Vec<u64>>::from_container(
			vec![0u64; polynomial_size.0],
			ciphertext_modulus
		);

	// Allocate the LweCiphertext to store the result of the PBS
	let mut pbs_multiplication_ct = LweCiphertext::new(
	    0u64,
	    big_lwe_sk.lwe_dimension().to_lwe_size(),
	    ciphertext_modulus,
	);
	println!("Performing blind rotation...");
	// blind_rotate_assign(&lwe_ciphertext_in, &mut accumulator, &fourier_bsk);
	let _new_accumulator_noise = blind_rotate_assign_ret_noise(
									&lwe_ciphertext_in, 
									&mut accumulator, 
									&fourier_bsk,
									&lwe_ciphertext_in_mask,
									&lwe_ciphertext_in_noise,
									// &accumulator_mask,
									// &accumulator_noise,
									bsk_mask_vector,
									bsk_noise_vector,
									);
	// for the updated accumulator, the mask is same as it's mask.
	let _new_accumulator_mask = accumulator.get_mask();
	// for the updated accumulator, the noise is a little complex and computed next.
	println!("Performing sample extraction...");
	extract_lwe_sample_from_glwe_ciphertext(
	    &accumulator,
	    &mut pbs_multiplication_ct,
	    MonomialDegree(0),
	);

	// Decrypt the PBS multiplication result
	let pbs_multiplication_plaintext: Plaintext<u64> =
	    decrypt_lwe_ciphertext(&big_lwe_sk, &pbs_multiplication_ct);

	// Create a SignedDecomposer to perform the rounding of the decrypted plaintext
	// We pass a DecompositionBaseLog of 5 and a DecompositionLevelCount of 1 indicating we want to
	// round the 5 MSB, 1 bit of padding plus our 4 bits of message
	let signed_decomposer =
	    SignedDecomposer::new(DecompositionBaseLog(5), DecompositionLevelCount(1));

	// Round and remove our encoding
	let pbs_multiplication_result: u64 =
	    signed_decomposer.closest_representable(pbs_multiplication_plaintext.0) / delta;

	println!("Checking result...");
	assert_eq!(6, pbs_multiplication_result);
	println!(
	    "Multiplication via PBS result is correct! Expected 6, got {pbs_multiplication_result}"
	);
}

fn test_sk_key_switch() {
	// DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
	// computations
	// Define parameters for LweKeyswitchKey creation
	let input_lwe_dimension = LweDimension(742);
	let lwe_noise_distribution =
	    Gaussian::from_dispersion_parameter(StandardDev(0.000007069849454709433), 0.0);
	let output_lwe_dimension = LweDimension(2048);
	let decomp_base_log = DecompositionBaseLog(3);
	let decomp_level_count = DecompositionLevelCount(5);
	let ciphertext_modulus = CiphertextModulus::new_native();

	// Create the PRNG
	let mut seeder = new_seeder();
	let seeder = seeder.as_mut();
	let mut encryption_generator =
	    EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
	let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

	// Create the LweSecretKey
	let input_lwe_secret_key =
	    allocate_and_generate_new_binary_lwe_secret_key(input_lwe_dimension, &mut secret_generator);
	let output_lwe_secret_key = allocate_and_generate_new_binary_lwe_secret_key(
	    output_lwe_dimension,
	    &mut secret_generator,
	);

	let ksk = allocate_and_generate_new_lwe_keyswitch_key(
	    &input_lwe_secret_key,
	    &output_lwe_secret_key,
	    decomp_base_log,
	    decomp_level_count,
	    lwe_noise_distribution,
	    ciphertext_modulus,
	    &mut encryption_generator,
	);

	let num_bits = 6;
    for val in 0..2u64.pow(num_bits) {
		// Create the plaintext
		let msg = val;
		// let msg = 3u64;
		let plaintext = Plaintext(msg << (64-num_bits));

		// Create a new LweCiphertext
		let input_lwe = allocate_and_encrypt_new_lwe_ciphertext(
		    &input_lwe_secret_key,
		    plaintext,
		    lwe_noise_distribution,
		    ciphertext_modulus,
		    &mut encryption_generator,
		);

		let mut output_lwe = LweCiphertext::new(
		    0,
		    output_lwe_secret_key.lwe_dimension().to_lwe_size(),
		    ciphertext_modulus,
		);

		keyswitch_lwe_ciphertext(&ksk, &input_lwe, &mut output_lwe);

		let decrypted_plaintext = decrypt_lwe_ciphertext(&output_lwe_secret_key, &output_lwe);

		// Round and remove encoding
		// First create a decomposer working on the high 4 bits corresponding to our encoding.
		let decomposer = SignedDecomposer::new(DecompositionBaseLog(num_bits.try_into().unwrap()), DecompositionLevelCount(1));

		let rounded = decomposer.closest_representable(decrypted_plaintext.0);

		// Remove the encoding
		let cleartext = rounded >> (64-num_bits);

		// Check we recovered the original message
		if cleartext != msg {
			println!("FAILED: decrypted value ({:?}) v/s actual value ({:?})", cleartext, msg);
		}	
		// assert_eq!(cleartext, msg);	
	}
}

fn test_sk_key_switch_det() {
	// DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
	// computations
	// Define parameters for LweKeyswitchKey creation
	let input_lwe_dimension = LweDimension(742);
	let lwe_noise_distribution =
	    Gaussian::from_dispersion_parameter(StandardDev(0.000007069849454709433), 0.0);
	let output_lwe_dimension = LweDimension(2048);
	let decomp_base_log = DecompositionBaseLog(3);
	let decomp_level_count = DecompositionLevelCount(5);
	let ciphertext_modulus = CiphertextModulus::new_native();

	// Create the PRNG
	let mut seeder = new_seeder();
	let seeder = seeder.as_mut();
	let mut encryption_generator =
	    EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
	let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

	// Create the LweSecretKey
	let input_lwe_secret_key =
	    allocate_and_generate_new_binary_lwe_secret_key(input_lwe_dimension, &mut secret_generator);
	let output_lwe_secret_key = allocate_and_generate_new_binary_lwe_secret_key(
	    output_lwe_dimension,
	    &mut secret_generator,
	);

	let (ksk, ksk_mask_vector, ksk_noise_vector, _msg_vector) = allocate_and_generate_new_lwe_keyswitch_key_ret_mask_and_noise(
	    &input_lwe_secret_key,
	    &output_lwe_secret_key,
	    decomp_base_log,
	    decomp_level_count,
	    lwe_noise_distribution,
	    ciphertext_modulus,
	    &mut encryption_generator,
	);

	let ksk2 = allocate_and_generate_new_lwe_keyswitch_key_deterministic(
	    &input_lwe_secret_key,
	    &output_lwe_secret_key,
	    decomp_base_log,
	    decomp_level_count,
	    lwe_noise_distribution,
	    ciphertext_modulus,
	    &mut encryption_generator,
	    &ksk_mask_vector,
	    &ksk_noise_vector,
	);

	assert_eq!(ksk, ksk2);
	println!("Deterministic ksk generation: correct");

	// Create the plaintext
	let msg = 3u64;
	let plaintext = Plaintext(msg << 60);

	// Create a new LweCiphertext
	let input_lwe = allocate_and_encrypt_new_lwe_ciphertext(
	    &input_lwe_secret_key,
	    plaintext,
	    lwe_noise_distribution,
	    ciphertext_modulus,
	    &mut encryption_generator,
	);

	let mut output_lwe = LweCiphertext::new(
	    0,
	    output_lwe_secret_key.lwe_dimension().to_lwe_size(),
	    ciphertext_modulus,
	);

	keyswitch_lwe_ciphertext(&ksk, &input_lwe, &mut output_lwe);

	let decrypted_plaintext = decrypt_lwe_ciphertext(&output_lwe_secret_key, &output_lwe);

	// Round and remove encoding
	// First create a decomposer working on the high 4 bits corresponding to our encoding.
	let decomposer = SignedDecomposer::new(DecompositionBaseLog(4), DecompositionLevelCount(1));

	let rounded = decomposer.closest_representable(decrypted_plaintext.0);

	// Remove the encoding
	let cleartext = rounded >> 60;

	// Check we recovered the original message
	assert_eq!(cleartext, msg);	
}

fn test_pk_key_switch(inp_lwe_dim : u64, out_lwe_dim : u64) {
	// DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
	// computations
	// Define parameters for LweKeyswitchKey creation
	// let input_lwe_dimension = LweDimension(4);
	// let input_lwe_dimension = LweDimension(20);
	// let input_lwe_dimension = LweDimension(100);
	// let input_lwe_dimension = LweDimension(742);
	// let input_lwe_dimension = LweDimension(2048);
	let input_lwe_dimension = LweDimension(inp_lwe_dim.try_into().unwrap());
	let lwe_noise_distribution =
	    // Gaussian::from_dispersion_parameter(StandardDev(0.000007069849454709433), 0.0);
	    Gaussian::from_dispersion_parameter(StandardDev(0.00000000000000029403601535432533), 0.0);
	// let output_lwe_dimension = LweDimension(100);
	// let output_lwe_dimension = LweDimension(742);
	// let output_lwe_dimension = LweDimension(2048);
	let output_lwe_dimension = LweDimension(out_lwe_dim.try_into().unwrap());
	let decomp_base_log = DecompositionBaseLog(3);
	let decomp_level_count = DecompositionLevelCount(5);
	let ciphertext_modulus = CiphertextModulus::new_native();

	// Create the PRNG
	println!("Creating PRNG...");
	let mut seeder = new_seeder();
	let seeder = seeder.as_mut();
	let mut encryption_generator =
	    EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
	let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
	let mut ksk_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

	// Create the LweSecretKey and LwePublicKey
	println!("Creating LWESecretKey...");
	let input_lwe_secret_key =
	    allocate_and_generate_new_binary_lwe_secret_key(input_lwe_dimension, &mut secret_generator);
	let output_lwe_secret_key = allocate_and_generate_new_binary_lwe_secret_key(
	    output_lwe_dimension,
	    &mut secret_generator,
	);
	println!("Creating LWEPublicKey...");
	let zero_encryption_count =
	    LwePublicKeyZeroEncryptionCount(output_lwe_dimension.to_lwe_size().0 * 64 + 128);
	let mut now = Instant::now();
	let output_lwe_public_key = allocate_and_generate_new_lwe_public_key(
	    &output_lwe_secret_key,
	    zero_encryption_count,
	    lwe_noise_distribution,
	    ciphertext_modulus,
	    &mut encryption_generator,
	);
	let pk_gen_time = now.elapsed();
	println!("Creating LWEPublicKey took {:?}", pk_gen_time);

	now = Instant::now();
	// let ksk = allocate_and_generate_new_lwe_keyswitch_key(
	println!("Creating key switching key with public key...");

	let ksk = allocate_and_generate_new_lwe_keyswitch_key_with_public_key(
	    &input_lwe_secret_key,
	    // &output_lwe_secret_key,
	    &output_lwe_public_key,
	    decomp_base_log,
	    decomp_level_count,
	    // lwe_noise_distribution,
	    ciphertext_modulus,
	    // &mut encryption_generator,
	    // &mut secret_generato/r,
	    &mut ksk_generator,
	);
	// println!("ksk: {:?}", ksk);
	let ksk_gen_time = now.elapsed();
	println!("Creating key switching key took {:?}", ksk_gen_time);


	// let num_bits : usize = 4;
	let num_bits = 8;
    // for val in 3u64..4u64 {
    for val in 0..2u64.pow(num_bits) {
		// Create the plaintext
		let msg = val;
		// let msg = 3u64;
		let plaintext = Plaintext(msg << (64-num_bits) );

		// Create a new LweCiphertext
		// println!("Encrypting...");
		let input_lwe = allocate_and_encrypt_new_lwe_ciphertext(
		    &input_lwe_secret_key,
		    plaintext,
		    lwe_noise_distribution,
		    ciphertext_modulus,
		    &mut encryption_generator,
		);

		let mut output_lwe = LweCiphertext::new(
		    0u64,
		    output_lwe_secret_key.lwe_dimension().to_lwe_size(),
		    ciphertext_modulus,
		);

		// println!("Key switching...");
		keyswitch_lwe_ciphertext(&ksk, &input_lwe, &mut output_lwe);

		// println!("Decrypting...");
		let decrypted_plaintext = decrypt_lwe_ciphertext(&output_lwe_secret_key, &output_lwe);

		// Round and remove encoding
		// First create a decomposer working on the high 4 bits corresponding to our encoding.
		let decomposer = SignedDecomposer::new(DecompositionBaseLog(num_bits.try_into().unwrap()), DecompositionLevelCount(1));

		let rounded = decomposer.closest_representable(decrypted_plaintext.0);

		// Remove the encoding
		let cleartext = rounded >> (64-num_bits);

		// Check we recovered the original message
		if cleartext != msg {
			println!("FAILED: decrypted value ({:?}) v/s actual value ({:?})", cleartext, msg);
		}	
		// assert_eq!(cleartext, msg);	
	}
}

fn test_pk_key_switch_det() {
	// DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
	// computations
	// Define parameters for LweKeyswitchKey creation
	// let input_lwe_dimension = LweDimension(742);
	let input_lwe_dimension = LweDimension(100);
	let lwe_noise_distribution =
	    Gaussian::from_dispersion_parameter(StandardDev(0.000007069849454709433), 0.0);
	// let output_lwe_dimension = LweDimension(2048);
	let output_lwe_dimension = LweDimension(100);
	let decomp_base_log = DecompositionBaseLog(3);
	let decomp_level_count = DecompositionLevelCount(5);
	let ciphertext_modulus = CiphertextModulus::new_native();

	// Create the PRNG
	let mut seeder = new_seeder();
	let seeder = seeder.as_mut();
	let mut encryption_generator =
	    EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
	let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
	let mut ksk_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

	// Create the LweSecretKey
	let input_lwe_secret_key =
	    allocate_and_generate_new_binary_lwe_secret_key(input_lwe_dimension, &mut secret_generator);
	let output_lwe_secret_key = allocate_and_generate_new_binary_lwe_secret_key(
	    output_lwe_dimension,
	    &mut secret_generator,
	);

	println!("Creating LWEPublicKey...");
	let zero_encryption_count =
	    LwePublicKeyZeroEncryptionCount(output_lwe_dimension.to_lwe_size().0 * 64 + 128);
	let mut now = Instant::now();
	let output_lwe_public_key = allocate_and_generate_new_lwe_public_key(
	    &output_lwe_secret_key,
	    zero_encryption_count,
	    lwe_noise_distribution,
	    ciphertext_modulus,
	    &mut encryption_generator,
	);
	let pk_gen_time = now.elapsed();
	println!("Creating LWEPublicKey took {:?}", pk_gen_time);

	now = Instant::now();
	let (ksk, ksk_mask_vector, _msg_vector) = allocate_and_generate_new_lwe_keyswitch_key_with_public_key_ret_mask(
	    &input_lwe_secret_key,
	    &output_lwe_public_key,
	    decomp_base_log,
	    decomp_level_count,
	    ciphertext_modulus,
	    &mut ksk_generator,
	);
	let ksk_gen_time = now.elapsed();
	println!("Creating key switching key took {:?}", ksk_gen_time);

	let ksk2 = allocate_and_generate_new_lwe_keyswitch_key_with_public_key_deterministic(
	    &input_lwe_secret_key,
	    &output_lwe_public_key,
	    decomp_base_log,
	    decomp_level_count,
	    ciphertext_modulus,
	    // &mut ksk_generator,
	    &ksk_mask_vector,
	);

	assert_eq!(ksk, ksk2);
	println!("Deterministic public key ksk generation: correct");

	// Create the plaintext
	let msg = 3u64;
	let plaintext = Plaintext(msg << 60);

	// Create a new LweCiphertext
	let input_lwe = allocate_and_encrypt_new_lwe_ciphertext(
	    &input_lwe_secret_key,
	    plaintext,
	    lwe_noise_distribution,
	    ciphertext_modulus,
	    &mut encryption_generator,
	);

	let mut output_lwe = LweCiphertext::new(
	    0,
	    output_lwe_secret_key.lwe_dimension().to_lwe_size(),
	    ciphertext_modulus,
	);

	keyswitch_lwe_ciphertext(&ksk, &input_lwe, &mut output_lwe);

	let decrypted_plaintext = decrypt_lwe_ciphertext(&output_lwe_secret_key, &output_lwe);

	// Round and remove encoding
	// First create a decomposer working on the high 4 bits corresponding to our encoding.
	let decomposer = SignedDecomposer::new(DecompositionBaseLog(4), DecompositionLevelCount(1));

	let rounded = decomposer.closest_representable(decrypted_plaintext.0);

	// Remove the encoding
	let cleartext = rounded >> 60;

	// Check we recovered the original message
	assert_eq!(cleartext, msg);	
}

fn test_sk_pbs(multiplier_val: u64) {
	// DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
	// computations
	// Define the parameters for a 4 bits message able to hold the doubled 2 bits message
	let small_lwe_dimension = LweDimension(742);
	let glwe_dimension = GlweDimension(1);
	let polynomial_size = PolynomialSize(2048);
	let lwe_noise_distribution =
	    Gaussian::from_dispersion_parameter(StandardDev(0.000007069849454709433), 0.0);
	let glwe_noise_distribution =
	    Gaussian::from_dispersion_parameter(StandardDev(0.00000000000000029403601535432533), 0.0);
	let pbs_base_log = DecompositionBaseLog(23);
	let pbs_level = DecompositionLevelCount(1);
	let ciphertext_modulus = CiphertextModulus::new_native();

	// Request the best seeder possible, starting with hardware entropy sources and falling back to
	// /dev/random on Unix systems if enabled via cargo features
	let mut boxed_seeder = new_seeder();
	// Get a mutable reference to the seeder as a trait object from the Box returned by new_seeder
	let seeder = boxed_seeder.as_mut();

	// Create a generator which uses a CSPRNG to generate secret keys
	let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

	// Create a generator which uses two CSPRNGs to generate public masks and secret encryption
	// noise
	let mut encryption_generator =
	    EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);

	println!("Generating keys...");

	// Generate an LweSecretKey with binary coefficients
	let small_lwe_sk =
	    LweSecretKey::generate_new_binary(small_lwe_dimension, &mut secret_generator);

	// Generate a GlweSecretKey with binary coefficients
	let glwe_sk =
	    GlweSecretKey::generate_new_binary(glwe_dimension, polynomial_size, &mut secret_generator);

	// Create a copy of the GlweSecretKey re-interpreted as an LweSecretKey
	let big_lwe_sk = glwe_sk.clone().into_lwe_secret_key();

	// Generate the seeded bootstrapping key to show how to handle entity decompression,
	// we use the parallel variant for performance reason
	let std_bootstrapping_key = par_allocate_and_generate_new_seeded_lwe_bootstrap_key(
	    &small_lwe_sk,
	    &glwe_sk,
	    pbs_base_log,
	    pbs_level,
	    glwe_noise_distribution,
	    ciphertext_modulus,
	    seeder,
	);

	// We decompress the bootstrapping key
	let std_bootstrapping_key: LweBootstrapKeyOwned<u64> =
	    std_bootstrapping_key.decompress_into_lwe_bootstrap_key();

	// Create the empty bootstrapping key in the Fourier domain
	let mut fourier_bsk = FourierLweBootstrapKey::new(
	    std_bootstrapping_key.input_lwe_dimension(),
	    std_bootstrapping_key.glwe_size(),
	    std_bootstrapping_key.polynomial_size(),
	    std_bootstrapping_key.decomposition_base_log(),
	    std_bootstrapping_key.decomposition_level_count(),
	);

	// Use the conversion function (a memory optimized version also exists but is more complicated
	// to use) to convert the standard bootstrapping key to the Fourier domain
	convert_standard_lwe_bootstrap_key_to_fourier(&std_bootstrapping_key, &mut fourier_bsk);
	// We don't need the standard bootstrapping key anymore
	drop(std_bootstrapping_key);

	// Our 4 bits message space
	let message_modulus = 1u64 << 4;

    for msg in 0..2u64.pow(MSG_BITS) {
		// Our input message
		// let input_message = 3u64;
		let input_message = msg;

		// Delta used to encode 4 bits of message + a bit of padding on u64
		let delta = (1_u64 << 63) / message_modulus;
		// let delta = (1_u64 << 62) / message_modulus;

		// Apply our encoding
		let plaintext = Plaintext(input_message * delta);

		// Allocate a new LweCiphertext and encrypt our plaintext
		let lwe_ciphertext_in: LweCiphertextOwned<u64> = allocate_and_encrypt_new_lwe_ciphertext(
		    &small_lwe_sk,
		    plaintext,
		    lwe_noise_distribution,
		    ciphertext_modulus,
		    &mut encryption_generator,
		);

		// Now we will use a PBS to compute a multiplication by 2, it is NOT the recommended way of
		// doing this operation in terms of performance as it's much more costly than a multiplication
		// with a cleartext, however it resets the noise in a ciphertext to a nominal level and allows
		// to evaluate arbitrary functions so depending on your use case it can be a better fit.

		// Generate the accumulator for our multiplication by 2 using a simple closure
		// let multiplier = 2u64;
		let multiplier = multiplier_val;
		let accumulator: GlweCiphertextOwned<u64> = generate_programmable_bootstrap_glwe_lut(
		    polynomial_size,
		    glwe_dimension.to_glwe_size(),
		    message_modulus as usize,
		    ciphertext_modulus,
		    delta,
		    |x: u64| multiplier * x,
		);
		// let expected_output_message = (multiplier * input_message) % message_modulus;
		let expected_output_message = multiplier * input_message;

		// Allocate the LweCiphertext to store the result of the PBS
		let mut pbs_multiplication_ct = LweCiphertext::new(
		    0u64,
		    big_lwe_sk.lwe_dimension().to_lwe_size(),
		    ciphertext_modulus,
		);
		println!("Computing PBS...");
		programmable_bootstrap_lwe_ciphertext(
		    &lwe_ciphertext_in,
		    &mut pbs_multiplication_ct,
		    &accumulator,
		    &fourier_bsk,
		);

		// Decrypt the PBS multiplication result
		let pbs_multiplication_plaintext: Plaintext<u64> =
		    decrypt_lwe_ciphertext(&big_lwe_sk, &pbs_multiplication_ct);
		// println!("pbs_multiplication_plaintext: {:?}", pbs_multiplication_plaintext);

		// Create a SignedDecomposer to perform the rounding of the decrypted plaintext
		// We pass a DecompositionBaseLog of 5 and a DecompositionLevelCount of 1 indicating we want to
		// round the 5 MSB, 1 bit of padding plus our 4 bits of message
		let signed_decomposer =
		    // SignedDecomposer::new(DecompositionBaseLog(5), DecompositionLevelCount(1));
		    SignedDecomposer::new(DecompositionBaseLog(6), DecompositionLevelCount(1));

		// println!("pbs_multiplication_plaintext closest_representable: {:?}", signed_decomposer.closest_representable(pbs_multiplication_plaintext.0));
		// Round and remove our encoding
		let pbs_multiplication_result: u64 =
		    signed_decomposer.closest_representable(pbs_multiplication_plaintext.0) / delta;
		// println!("pbs_multiplication_result: {:?}", pbs_multiplication_result);

		println!("Checking result...");
		assert_eq!(expected_output_message, pbs_multiplication_result);
		println!(
		    "Multiplication via PBS result is correct! Expected {expected_output_message}, got {pbs_multiplication_result}"
		);
	}
}

fn test_sk_pbs_full() {
	// DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
	// computations
	// Define the parameters for a 4 bits message able to hold the doubled 2 bits message
	let small_lwe_dimension = LweDimension(742);
	let glwe_dimension = GlweDimension(1);
	let polynomial_size = PolynomialSize(2048);
	let lwe_noise_distribution =
	    Gaussian::from_dispersion_parameter(StandardDev(0.000007069849454709433), 0.0);
	let glwe_noise_distribution =
	    Gaussian::from_dispersion_parameter(StandardDev(0.00000000000000029403601535432533), 0.0);
	let pbs_base_log = DecompositionBaseLog(23);
	let pbs_level = DecompositionLevelCount(1);
	let ciphertext_modulus = CiphertextModulus::new_native();

	let ksk_decomp_base_log = DecompositionBaseLog(3);
	let ksk_decomp_level_count = DecompositionLevelCount(5);

	// Request the best seeder possible, starting with hardware entropy sources and falling back to
	// /dev/random on Unix systems if enabled via cargo features
	let mut boxed_seeder = new_seeder();
	// Get a mutable reference to the seeder as a trait object from the Box returned by new_seeder
	let seeder = boxed_seeder.as_mut();

	// Create a generator which uses a CSPRNG to generate secret keys
	let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

	// Create a generator which uses two CSPRNGs to generate public masks and secret encryption
	// noise
	let mut encryption_generator =
	    EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);

	println!("Generating keys...");

	// Generate an LweSecretKey with binary coefficients
	let small_lwe_sk =
	    LweSecretKey::generate_new_binary(small_lwe_dimension, &mut secret_generator);

	// Generate a GlweSecretKey with binary coefficients
	let glwe_sk =
	    GlweSecretKey::generate_new_binary(glwe_dimension, polynomial_size, &mut secret_generator);

	// Create a copy of the GlweSecretKey re-interpreted as an LweSecretKey
	let big_lwe_sk = glwe_sk.clone().into_lwe_secret_key();

	// Create keyswitch key to switch from big_lwe_sk to small_lwe_sk
	let ksk = allocate_and_generate_new_lwe_keyswitch_key(
	    &big_lwe_sk,
	    &small_lwe_sk,
	    ksk_decomp_base_log,
	    ksk_decomp_level_count,
	    lwe_noise_distribution,
	    ciphertext_modulus,
	    &mut encryption_generator,
	);

	// Generate the seeded bootstrapping key to show how to handle entity decompression,
	// we use the parallel variant for performance reason
	let std_bootstrapping_key = par_allocate_and_generate_new_seeded_lwe_bootstrap_key(
	    &small_lwe_sk,
	    &glwe_sk,
	    pbs_base_log,
	    pbs_level,
	    glwe_noise_distribution,
	    ciphertext_modulus,
	    seeder,
	);

	// We decompress the bootstrapping key
	let std_bootstrapping_key: LweBootstrapKeyOwned<u64> =
	    std_bootstrapping_key.decompress_into_lwe_bootstrap_key();

	// Create the empty bootstrapping key in the Fourier domain
	let mut fourier_bsk = FourierLweBootstrapKey::new(
	    std_bootstrapping_key.input_lwe_dimension(),
	    std_bootstrapping_key.glwe_size(),
	    std_bootstrapping_key.polynomial_size(),
	    std_bootstrapping_key.decomposition_base_log(),
	    std_bootstrapping_key.decomposition_level_count(),
	);

	// Use the conversion function (a memory optimized version also exists but is more complicated
	// to use) to convert the standard bootstrapping key to the Fourier domain
	convert_standard_lwe_bootstrap_key_to_fourier(&std_bootstrapping_key, &mut fourier_bsk);
	// We don't need the standard bootstrapping key anymore
	drop(std_bootstrapping_key);

	// Our 4 bits message space
	// let message_modulus = 1u64 << 4;
	let message_modulus = 1u64 << MSG_BITS;

    for msg in 0..2u64.pow(MSG_BITS) {
		// Our input message
		let input_message = msg;
		// let input_message = 3u64;

		// Delta used to encode 4 bits of message + a bit of padding on u64
		let delta = (1_u64 << 63) / message_modulus;
		// let delta = (1_u64 << 62) / message_modulus;

		// Apply our encoding
		let plaintext = Plaintext(input_message * delta);

		// Allocate a new LweCiphertext and encrypt our plaintext
		let lwe_ciphertext_in: LweCiphertextOwned<u64> = allocate_and_encrypt_new_lwe_ciphertext(
		    &small_lwe_sk,
		    plaintext,
		    lwe_noise_distribution,
		    ciphertext_modulus,
		    &mut encryption_generator,
		);

		// Now we will use a PBS to compute a multiplication by 2, it is NOT the recommended way of
		// doing this operation in terms of performance as it's much more costly than a multiplication
		// with a cleartext, however it resets the noise in a ciphertext to a nominal level and allows
		// to evaluate arbitrary functions so depending on your use case it can be a better fit.

		// Generate the accumulator for our multiplication by 2 using a simple closure
		let multiplier = 2u64;
		let accumulator: GlweCiphertextOwned<u64> = generate_programmable_bootstrap_glwe_lut(
		    polynomial_size,
		    glwe_dimension.to_glwe_size(),
		    message_modulus as usize,
		    ciphertext_modulus,
		    delta,
		    |x: u64| multiplier * x,
		);
		// let expected_output_message = (multiplier * input_message) % message_modulus;
		let expected_output_message = multiplier * input_message;

		// Allocate the LweCiphertext to store the result of the PBS
		let mut pbs_multiplication_ct = LweCiphertext::new(
		    0u64,
		    big_lwe_sk.lwe_dimension().to_lwe_size(),
		    ciphertext_modulus,
		);
		println!("Computing PBS...");
		programmable_bootstrap_lwe_ciphertext(
		    &lwe_ciphertext_in,
		    &mut pbs_multiplication_ct,
		    &accumulator,
		    &fourier_bsk,
		);

		// Allocate the LWeCiphertext to store the result of the key switch
		let mut key_switch_ct = LweCiphertext::new(
		    0u64,
		    small_lwe_sk.lwe_dimension().to_lwe_size(),
		    ciphertext_modulus,
		);
		println!("Key switching...");
		keyswitch_lwe_ciphertext(&ksk, &pbs_multiplication_ct, &mut key_switch_ct);

		// Decrypt the PBS multiplication result
		// let pbs_multiplication_plaintext: Plaintext<u64> =
		//     decrypt_lwe_ciphertext(&big_lwe_sk, &pbs_multiplication_ct);
		let key_switch_plaintext = decrypt_lwe_ciphertext(&small_lwe_sk, &key_switch_ct);

		// Create a SignedDecomposer to perform the rounding of the decrypted plaintext
		// We pass a DecompositionBaseLog of 5 and a DecompositionLevelCount of 1 indicating we want to
		// round the 5 MSB, 1 bit of padding plus our 4 bits of message
		let signed_decomposer =
		    SignedDecomposer::new(DecompositionBaseLog(5), DecompositionLevelCount(1));

		// Round and remove our encoding
		let key_switch_result: u64 =
		    signed_decomposer.closest_representable(key_switch_plaintext.0) / delta;
		// let pbs_multiplication_result: u64 =
		//     signed_decomposer.closest_representable(pbs_multiplication_plaintext.0) / delta;

		println!("Checking result...");
		assert_eq!(expected_output_message, key_switch_result);
		// assert_eq!(6, pbs_multiplication_result);
		println!(
		    "Multiplication via PBS, followed by key switch result is correct! Expected {expected_output_message}, got {key_switch_result}"
		    // "Multiplication via PBS, followed by key switch result is correct! Expected 6, got {pbs_multiplication_result}"
		);
	}
}

fn test_sk_pbs_full_det() {
	// DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
	// computations
	// Define the parameters for a 4 bits message able to hold the doubled 2 bits message
	let small_lwe_dimension = LweDimension(742);
	let glwe_dimension = GlweDimension(1);
	let polynomial_size = PolynomialSize(2048);
	let lwe_noise_distribution =
	    Gaussian::from_dispersion_parameter(StandardDev(0.000007069849454709433), 0.0);
	let glwe_noise_distribution =
	    Gaussian::from_dispersion_parameter(StandardDev(0.00000000000000029403601535432533), 0.0);
	let pbs_base_log = DecompositionBaseLog(23);
	let pbs_level = DecompositionLevelCount(1);
	let ciphertext_modulus = CiphertextModulus::new_native();

	let ksk_decomp_base_log = DecompositionBaseLog(3);
	let ksk_decomp_level_count = DecompositionLevelCount(5);

	// Request the best seeder possible, starting with hardware entropy sources and falling back to
	// /dev/random on Unix systems if enabled via cargo features
	let mut boxed_seeder = new_seeder();
	// Get a mutable reference to the seeder as a trait object from the Box returned by new_seeder
	let seeder = boxed_seeder.as_mut();

	// Create a generator which uses a CSPRNG to generate secret keys
	let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

	// Create a generator which uses two CSPRNGs to generate public masks and secret encryption
	// noise
	let mut encryption_generator =
	    EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);

	println!("Generating keys...");

	// Generate an LweSecretKey with binary coefficients
	let small_lwe_sk =
	    LweSecretKey::generate_new_binary(small_lwe_dimension, &mut secret_generator);

	// Generate a GlweSecretKey with binary coefficients
	let glwe_sk =
	    GlweSecretKey::generate_new_binary(glwe_dimension, polynomial_size, &mut secret_generator);

	// Create a copy of the GlweSecretKey re-interpreted as an LweSecretKey
	let big_lwe_sk = glwe_sk.clone().into_lwe_secret_key();

	// Create keyswitch key to switch from big_lwe_sk to small_lwe_sk
	// TODO: build up towards allocate_and_generate_new_lwe_keyswitch_key_ret_mask_and_noise
	let (ksk, _ksk_mask_vector, ksk_noise_vector, msg_vector) = allocate_and_generate_new_lwe_keyswitch_key_ret_mask_and_noise(
	// let ksk = allocate_and_generate_new_lwe_keyswitch_key(
	    &big_lwe_sk,
	    &small_lwe_sk,
	    ksk_decomp_base_log,
	    ksk_decomp_level_count,
	    lwe_noise_distribution,
	    ciphertext_modulus,
	    &mut encryption_generator,
	);

	// Generate the seeded bootstrapping key to show how to handle entity decompression,
	// we use the parallel variant for performance reason
	let std_bootstrapping_key = par_allocate_and_generate_new_seeded_lwe_bootstrap_key(
	    &small_lwe_sk,
	    &glwe_sk,
	    pbs_base_log,
	    pbs_level,
	    glwe_noise_distribution,
	    ciphertext_modulus,
	    seeder,
	);

	// We decompress the bootstrapping key
	let std_bootstrapping_key: LweBootstrapKeyOwned<u64> =
	    std_bootstrapping_key.decompress_into_lwe_bootstrap_key();

	// Create the empty bootstrapping key in the Fourier domain
	let mut fourier_bsk = FourierLweBootstrapKey::new(
	    std_bootstrapping_key.input_lwe_dimension(),
	    std_bootstrapping_key.glwe_size(),
	    std_bootstrapping_key.polynomial_size(),
	    std_bootstrapping_key.decomposition_base_log(),
	    std_bootstrapping_key.decomposition_level_count(),
	);

	// Use the conversion function (a memory optimized version also exists but is more complicated
	// to use) to convert the standard bootstrapping key to the Fourier domain
	convert_standard_lwe_bootstrap_key_to_fourier(&std_bootstrapping_key, &mut fourier_bsk);
	// We don't need the standard bootstrapping key anymore
	drop(std_bootstrapping_key);

	// Our 4 bits message space
	// let message_modulus = 1u64 << 4;
	let message_modulus = 1u64 << MSG_BITS;

    for msg in 0..2u64.pow(MSG_BITS) {
		// Our input message
		let input_message = msg;
		// let input_message = 3u64;

		// Delta used to encode 4 bits of message + a bit of padding on u64
		let delta = (1_u64 << 63) / message_modulus;
		// let delta = (1_u64 << 62) / message_modulus;

		// Apply our encoding
		let plaintext = Plaintext(input_message * delta);

		// Allocate a new LweCiphertext and encrypt our plaintext
		let lwe_ciphertext_in: LweCiphertextOwned<u64> = allocate_and_encrypt_new_lwe_ciphertext(
		    &small_lwe_sk,
		    plaintext,
		    lwe_noise_distribution,
		    ciphertext_modulus,
		    &mut encryption_generator,
		);

		// Now we will use a PBS to compute a multiplication by 2, it is NOT the recommended way of
		// doing this operation in terms of performance as it's much more costly than a multiplication
		// with a cleartext, however it resets the noise in a ciphertext to a nominal level and allows
		// to evaluate arbitrary functions so depending on your use case it can be a better fit.

		// Generate the accumulator for our multiplication by 2 using a simple closure
		let multiplier = 2u64;
		let accumulator: GlweCiphertextOwned<u64> = generate_programmable_bootstrap_glwe_lut(
		    polynomial_size,
		    glwe_dimension.to_glwe_size(),
		    message_modulus as usize,
		    ciphertext_modulus,
		    delta,
		    |x: u64| multiplier * x,
		);
		// let expected_output_message = (multiplier * input_message) % message_modulus;
		let expected_output_message = multiplier * input_message;
		let expected_plaintext = Plaintext(expected_output_message * delta);

		// Allocate the LweCiphertext to store the result of the PBS
		let mut pbs_multiplication_ct = LweCiphertext::new(
		    0u64,
		    big_lwe_sk.lwe_dimension().to_lwe_size(),
		    ciphertext_modulus,
		);
		println!("Computing PBS...");
		programmable_bootstrap_lwe_ciphertext(
		    &lwe_ciphertext_in,
		    &mut pbs_multiplication_ct,
		    &accumulator,
		    &fourier_bsk,
		);

		// Allocate the LWeCiphertext to store the result of the key switch
		let mut key_switch_ct = LweCiphertext::new(
		    0u64,
		    small_lwe_sk.lwe_dimension().to_lwe_size(),
		    ciphertext_modulus,
		);

		println!("Key switching...");
		// keyswitch_lwe_ciphertext(&ksk, &pbs_multiplication_ct, &mut key_switch_ct);
		let (key_switch_noise, noisy_message) = keyswitch_lwe_ciphertext_ret_noise(&ksk, &pbs_multiplication_ct, &mut key_switch_ct, &ksk_noise_vector, &msg_vector);
    	let mut key_switch_mask = LweMask::from_container(
            vec![
                0u64; 
                small_lwe_sk.lwe_dimension().0
            ], 
            ciphertext_modulus);
        key_switch_mask.as_mut().copy_from_slice(key_switch_ct.get_mask().as_ref());
		// let key_switch_mask = key_switch_ct.get_mask();

		// Test if deterministic encryption matches for key_switch_ct
		let mut key_switch_ct_deterministic = LweCiphertext::new(
		    0u64,
		    small_lwe_sk.lwe_dimension().to_lwe_size(),
		    ciphertext_modulus,
		);
        encrypt_lwe_ciphertext_deterministic(
            &small_lwe_sk,
            &mut key_switch_ct_deterministic,
            noisy_message,
            // expected_plaintext,
            lwe_noise_distribution,
            &mut encryption_generator,
            &key_switch_mask,
            &key_switch_noise,
        );
        let mut diff_plaintext = expected_plaintext.0;
        diff_plaintext = diff_plaintext.wrapping_sub(noisy_message.0);
        println!("1: expected_plaintext: {:?}, noisy_message: {:?}, diff: {:?}", expected_plaintext, noisy_message, diff_plaintext);
        println!("2: expected_plaintext: {:?}, noisy_message: {:?}, diff: {:?}", expected_plaintext.0 / delta, noisy_message.0 / delta, diff_plaintext / delta);
        assert_eq!(key_switch_ct, key_switch_ct_deterministic);
		println!("Deterministic programmable bootstrapping: correct");
        
		// Decrypt the PBS multiplication result
		// let pbs_multiplication_plaintext: Plaintext<u64> =
		//     decrypt_lwe_ciphertext(&big_lwe_sk, &pbs_multiplication_ct);
		let key_switch_plaintext = decrypt_lwe_ciphertext(&small_lwe_sk, &key_switch_ct);

		// Create a SignedDecomposer to perform the rounding of the decrypted plaintext
		// We pass a DecompositionBaseLog of 5 and a DecompositionLevelCount of 1 indicating we want to
		// round the 5 MSB, 1 bit of padding plus our 4 bits of message
		let signed_decomposer =
		    SignedDecomposer::new(DecompositionBaseLog(5), DecompositionLevelCount(1));

		// Round and remove our encoding
		let key_switch_result: u64 =
		    signed_decomposer.closest_representable(key_switch_plaintext.0) / delta;
		// let pbs_multiplication_result: u64 =
		//     signed_decomposer.closest_representable(pbs_multiplication_plaintext.0) / delta;
		let expected_plaintext_rounded: u64 =
		    signed_decomposer.closest_representable(expected_plaintext.0);
		let expected_plaintext_rounded_decoded = expected_plaintext_rounded / delta;
		let noisy_message_rounded: u64 =
		    signed_decomposer.closest_representable(noisy_message.0);
		let noisy_message_rounded_decoded = noisy_message_rounded / delta;
        println!("3: expected_plaintext: {:?}, noisy_message: {:?}", expected_plaintext_rounded, noisy_message_rounded);
        println!("4: expected_plaintext: {:?}, noisy_message: {:?}", expected_plaintext_rounded_decoded, noisy_message_rounded_decoded);


		println!("Checking result...");
		assert_eq!(expected_output_message, key_switch_result);
		// assert_eq!(6, pbs_multiplication_result);
		println!(
		    "Multiplication via PBS, followed by key switch result is correct! Expected {expected_output_message}, got {key_switch_result}"
		    // "Multiplication via PBS, followed by key switch result is correct! Expected 6, got {pbs_multiplication_result}"
		);
	}
}

fn test_sk_pbs_det() {
	// DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
	// computations
	// Define the parameters for a 4 bits message able to hold the doubled 2 bits message
	let small_lwe_dimension = LweDimension(742);
	let glwe_dimension = GlweDimension(1);
	let polynomial_size = PolynomialSize(2048);
	let lwe_noise_distribution =
	    Gaussian::from_dispersion_parameter(StandardDev(0.000007069849454709433), 0.0);
	let glwe_noise_distribution =
	    Gaussian::from_dispersion_parameter(StandardDev(0.00000000000000029403601535432533), 0.0);
	let pbs_base_log = DecompositionBaseLog(23);
	let pbs_level = DecompositionLevelCount(1);
	let ciphertext_modulus = CiphertextModulus::new_native();

	// Request the best seeder possible, starting with hardware entropy sources and falling back to
	// /dev/random on Unix systems if enabled via cargo features
	let mut boxed_seeder = new_seeder();
	// Get a mutable reference to the seeder as a trait object from the Box returned by new_seeder
	let seeder = boxed_seeder.as_mut();

	// Create a generator which uses a CSPRNG to generate secret keys
	let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

	// Create a generator which uses two CSPRNGs to generate public masks and secret encryption
	// noise
	let mut encryption_generator =
	    EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);

	println!("Generating keys...");

	// Generate an LweSecretKey with binary coefficients
	let small_lwe_sk =
	    LweSecretKey::generate_new_binary(small_lwe_dimension, &mut secret_generator);

	// Generate a GlweSecretKey with binary coefficients
	let glwe_sk =
	    GlweSecretKey::generate_new_binary(glwe_dimension, polynomial_size, &mut secret_generator);

	// Create a copy of the GlweSecretKey re-interpreted as an LweSecretKey
	let big_lwe_sk = glwe_sk.clone().into_lwe_secret_key();

	// Generate the seeded bootstrapping key to show how to handle entity decompression,
	// we use the parallel variant for performance reason
	let (std_bootstrapping_key, _bsk_mask_vector, _bsk_noise_vector) = par_allocate_and_generate_new_seeded_lwe_bootstrap_key_ret_mask_and_noise(
	    &small_lwe_sk,
	    &glwe_sk,
	    pbs_base_log,
	    pbs_level,
	    glwe_noise_distribution,
	    ciphertext_modulus,
	    seeder,
	);

	// We decompress the bootstrapping key
	let std_bootstrapping_key: LweBootstrapKeyOwned<u64> =
	    std_bootstrapping_key.decompress_into_lwe_bootstrap_key();

	// Create the empty bootstrapping key in the Fourier domain
	let mut fourier_bsk = FourierLweBootstrapKey::new(
	    std_bootstrapping_key.input_lwe_dimension(),
	    std_bootstrapping_key.glwe_size(),
	    std_bootstrapping_key.polynomial_size(),
	    std_bootstrapping_key.decomposition_base_log(),
	    std_bootstrapping_key.decomposition_level_count(),
	);

	// Use the conversion function (a memory optimized version also exists but is more complicated
	// to use) to convert the standard bootstrapping key to the Fourier domain
	convert_standard_lwe_bootstrap_key_to_fourier(&std_bootstrapping_key, &mut fourier_bsk);
	// We don't need the standard bootstrapping key anymore
	drop(std_bootstrapping_key);

	// Our 4 bits message space
	let message_modulus = 1u64 << 4;

	// Our input message
	let input_message = 3u64;

	// Delta used to encode 4 bits of message + a bit of padding on u64
	let delta = (1_u64 << 63) / message_modulus;

	// Apply our encoding
	let plaintext = Plaintext(input_message * delta);

	// Allocate a new LweCiphertext and encrypt our plaintext
	let (lwe_ciphertext_in, _lwe_ciphertext_in_noise) : (LweCiphertextOwned<u64>, LweBody<u64>) = allocate_and_encrypt_new_lwe_ciphertext_ret_noise(
	    &small_lwe_sk,
	    plaintext,
	    lwe_noise_distribution,
	    ciphertext_modulus,
	    &mut encryption_generator,
	);
	let _lwe_ciphertext_in_mask = lwe_ciphertext_in.get_mask();

	// Now we will use a PBS to compute a multiplication by 2, it is NOT the recommended way of
	// doing this operation in terms of performance as it's much more costly than a multiplication
	// with a cleartext, however it resets the noise in a ciphertext to a nominal level and allows
	// to evaluate arbitrary functions so depending on your use case it can be a better fit.

	// Generate the accumulator for our multiplication by 2 using a simple closure
	let accumulator: GlweCiphertextOwned<u64> = generate_programmable_bootstrap_glwe_lut(
	    polynomial_size,
	    glwe_dimension.to_glwe_size(),
	    message_modulus as usize,
	    ciphertext_modulus,
	    delta,
	    |x: u64| 2 * x,
	);
	let _accumulator_mask = accumulator.get_mask();
	let _accumulator_noise = GlweBody::<Vec<u64>>::from_container(
			vec![0u64; polynomial_size.0],
			ciphertext_modulus
		);

	// Allocate the LweCiphertext to store the result of the PBS
	let mut pbs_multiplication_ct = LweCiphertext::new(
	    0u64,
	    big_lwe_sk.lwe_dimension().to_lwe_size(),
	    ciphertext_modulus,
	);
	println!("Computing PBS...");
	programmable_bootstrap_lwe_ciphertext(
	    &lwe_ciphertext_in,
	    &mut pbs_multiplication_ct,
	    &accumulator,
	    &fourier_bsk,
	);

	// Decrypt the PBS multiplication result
	let pbs_multiplication_plaintext: Plaintext<u64> =
	    decrypt_lwe_ciphertext(&big_lwe_sk, &pbs_multiplication_ct);

	// Create a SignedDecomposer to perform the rounding of the decrypted plaintext
	// We pass a DecompositionBaseLog of 5 and a DecompositionLevelCount of 1 indicating we want to
	// round the 5 MSB, 1 bit of padding plus our 4 bits of message
	let signed_decomposer =
	    SignedDecomposer::new(DecompositionBaseLog(5), DecompositionLevelCount(1));

	// Round and remove our encoding
	let pbs_multiplication_result: u64 =
	    signed_decomposer.closest_representable(pbs_multiplication_plaintext.0) / delta;

	println!("Checking result...");
	assert_eq!(6, pbs_multiplication_result);
	println!(
	    "Multiplication via PBS result is correct! Expected 6, got {pbs_multiplication_result}"
	);
}

fn test_pk_pbs_full() {
	// DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
	// computations
	// Define the parameters for a 4 bits message able to hold the doubled 2 bits message
	// let small_lwe_dimension = LweDimension(742);
	let small_lwe_dimension = LweDimension(128);
	let glwe_dimension = GlweDimension(1);
	// let polynomial_size = PolynomialSize(2048);
	let polynomial_size = PolynomialSize(256);
	let lwe_noise_distribution =
	    Gaussian::from_dispersion_parameter(StandardDev(0.000007069849454709433), 0.0);
	let ksk_noise_distribution =
	    Gaussian::from_dispersion_parameter(StandardDev(0.00000000000000029403601535432533), 0.0);
	let glwe_noise_distribution =
	    Gaussian::from_dispersion_parameter(StandardDev(0.00000000000000029403601535432533), 0.0);
	let pbs_base_log = DecompositionBaseLog(23);
	let pbs_level = DecompositionLevelCount(1);
	let ciphertext_modulus = CiphertextModulus::new_native();

	let ksk_decomp_base_log = DecompositionBaseLog(3);
	let ksk_decomp_level_count = DecompositionLevelCount(5);

	// Request the best seeder possible, starting with hardware entropy sources and falling back to
	// /dev/random on Unix systems if enabled via cargo features
	let mut boxed_seeder = new_seeder();
	// Get a mutable reference to the seeder as a trait object from the Box returned by new_seeder
	let seeder = boxed_seeder.as_mut();

	// Create a generator which uses a CSPRNG to generate secret keys
	let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
	let mut ksk_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

	// Create a generator which uses two CSPRNGs to generate public masks and secret encryption
	// noise
	let mut encryption_generator =
	    EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);

	println!("Generating keys...");

	// Generate an LweSecretKey with binary coefficients
	let small_lwe_sk =
	    LweSecretKey::generate_new_binary(small_lwe_dimension, &mut secret_generator);
	println!("Creating LWEPublicKey...");
	let zero_encryption_count =
	    LwePublicKeyZeroEncryptionCount(small_lwe_dimension.to_lwe_size().0 * 64 + 128);
	let mut now = Instant::now();
	let small_lwe_pk = allocate_and_generate_new_lwe_public_key(
	    &small_lwe_sk,
	    zero_encryption_count,
	    ksk_noise_distribution,
	    ciphertext_modulus,
	    &mut encryption_generator,
	);
	let pk_gen_time = now.elapsed();
	println!("Creating LWEPublicKey took {:?}", pk_gen_time);

	// Generate a GlweSecretKey with binary coefficients
	let glwe_sk =
	    GlweSecretKey::generate_new_binary(glwe_dimension, polynomial_size, &mut secret_generator);

	// Create a copy of the GlweSecretKey re-interpreted as an LweSecretKey
	let big_lwe_sk = glwe_sk.clone().into_lwe_secret_key();
	println!("big_lwe_sk dimension: {:?}", big_lwe_sk.lwe_dimension());

	now = Instant::now();
	println!("Creating key switching key with public key...");
	// Create keyswitch key to switch from big_lwe_sk to small_lwe_sk
	// let ksk = allocate_and_generate_new_lwe_keyswitch_key(
	let ksk = allocate_and_generate_new_lwe_keyswitch_key_with_public_key(
	    &big_lwe_sk,
	    // &small_lwe_sk,
	    &small_lwe_pk,
	    ksk_decomp_base_log,
	    ksk_decomp_level_count,
	    // lwe_noise_distribution,
	    ciphertext_modulus,
	    &mut ksk_generator,
	);
	let ksk_gen_time = now.elapsed();
	println!("Creating key switching key took {:?}", ksk_gen_time);

	// Generate the seeded bootstrapping key to show how to handle entity decompression,
	// we use the parallel variant for performance reason
	let std_bootstrapping_key = par_allocate_and_generate_new_seeded_lwe_bootstrap_key(
	    &small_lwe_sk,
	    &glwe_sk,
	    pbs_base_log,
	    pbs_level,
	    glwe_noise_distribution,
	    ciphertext_modulus,
	    seeder,
	);

	// We decompress the bootstrapping key
	let std_bootstrapping_key: LweBootstrapKeyOwned<u64> =
	    std_bootstrapping_key.decompress_into_lwe_bootstrap_key();

	// Create the empty bootstrapping key in the Fourier domain
	let mut fourier_bsk = FourierLweBootstrapKey::new(
	    std_bootstrapping_key.input_lwe_dimension(),
	    std_bootstrapping_key.glwe_size(),
	    std_bootstrapping_key.polynomial_size(),
	    std_bootstrapping_key.decomposition_base_log(),
	    std_bootstrapping_key.decomposition_level_count(),
	);

	// Use the conversion function (a memory optimized version also exists but is more complicated
	// to use) to convert the standard bootstrapping key to the Fourier domain
	convert_standard_lwe_bootstrap_key_to_fourier(&std_bootstrapping_key, &mut fourier_bsk);
	// We don't need the standard bootstrapping key anymore
	drop(std_bootstrapping_key);

	// Our 4 bits message space
	// let message_modulus = 1u64 << 4;
	let message_modulus = 1u64 << MSG_BITS;

    for msg in 0..2u64.pow(MSG_BITS) {
		// Our input message
		let input_message = msg;
		// let input_message = 3u64;

		// Delta used to encode 4 bits of message + a bit of padding on u64
		let delta = (1_u64 << 63) / message_modulus;
		// let delta = (1_u64 << 62) / message_modulus;

		// Apply our encoding
		let plaintext = Plaintext(input_message * delta);

		// Allocate a new LweCiphertext and encrypt our plaintext
		let lwe_ciphertext_in: LweCiphertextOwned<u64> = allocate_and_encrypt_new_lwe_ciphertext(
		    &small_lwe_sk,
		    plaintext,
		    lwe_noise_distribution,
		    ciphertext_modulus,
		    &mut encryption_generator,
		);

		// Now we will use a PBS to compute a multiplication by 2, it is NOT the recommended way of
		// doing this operation in terms of performance as it's much more costly than a multiplication
		// with a cleartext, however it resets the noise in a ciphertext to a nominal level and allows
		// to evaluate arbitrary functions so depending on your use case it can be a better fit.

		// Generate the accumulator for our multiplication by 2 using a simple closure
		let multiplier = 2u64;
		let accumulator: GlweCiphertextOwned<u64> = generate_programmable_bootstrap_glwe_lut(
		    polynomial_size,
		    glwe_dimension.to_glwe_size(),
		    message_modulus as usize,
		    ciphertext_modulus,
		    delta,
		    |x: u64| multiplier * x,
		);
		// let expected_output_message = (multiplier * input_message) % message_modulus;
		let expected_output_message = multiplier * input_message;

		// Allocate the LweCiphertext to store the result of the PBS
		let mut pbs_multiplication_ct = LweCiphertext::new(
		    0u64,
		    big_lwe_sk.lwe_dimension().to_lwe_size(),
		    ciphertext_modulus,
		);
		println!("Computing PBS...");
		programmable_bootstrap_lwe_ciphertext(
		    &lwe_ciphertext_in,
		    &mut pbs_multiplication_ct,
		    &accumulator,
		    &fourier_bsk,
		);

		// Allocate the LWeCiphertext to store the result of the key switch
		let mut key_switch_ct = LweCiphertext::new(
		    0u64,
		    small_lwe_sk.lwe_dimension().to_lwe_size(),
		    ciphertext_modulus,
		);
		println!("Key switching...");
		keyswitch_lwe_ciphertext(&ksk, &pbs_multiplication_ct, &mut key_switch_ct);

		// Decrypt the PBS multiplication result
		// let pbs_multiplication_plaintext: Plaintext<u64> =
		//     decrypt_lwe_ciphertext(&big_lwe_sk, &pbs_multiplication_ct);
		let key_switch_plaintext = decrypt_lwe_ciphertext(&small_lwe_sk, &key_switch_ct);

		// Create a SignedDecomposer to perform the rounding of the decrypted plaintext
		// We pass a DecompositionBaseLog of 5 and a DecompositionLevelCount of 1 indicating we want to
		// round the 5 MSB, 1 bit of padding plus our 4 bits of message
		let signed_decomposer =
		    SignedDecomposer::new(DecompositionBaseLog(5), DecompositionLevelCount(1));

		// Round and remove our encoding
		let key_switch_result: u64 =
		    signed_decomposer.closest_representable(key_switch_plaintext.0) / delta;
		// let pbs_multiplication_result: u64 =
		//     signed_decomposer.closest_representable(pbs_multiplication_plaintext.0) / delta;

		println!("Checking result...");
		assert_eq!(expected_output_message, key_switch_result);
		// assert_eq!(6, pbs_multiplication_result);
		println!(
		    "Multiplication via PBS, followed by key switch result is correct! Expected {expected_output_message}, got {key_switch_result}"
		    // "Multiplication via PBS, followed by key switch result is correct! Expected 6, got {pbs_multiplication_result}"
		);
	}
}

fn test_pk_pbs_full_det() {
	// DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
	// computations
	// Define the parameters for a 4 bits message able to hold the doubled 2 bits message
	// let small_lwe_dimension = LweDimension(742);
	let small_lwe_dimension = LweDimension(128);
	let glwe_dimension = GlweDimension(1);
	// let polynomial_size = PolynomialSize(2048);
	let polynomial_size = PolynomialSize(256);
	let lwe_noise_distribution =
	    Gaussian::from_dispersion_parameter(StandardDev(0.000007069849454709433), 0.0);
	let ksk_noise_distribution =
	    Gaussian::from_dispersion_parameter(StandardDev(0.00000000000000029403601535432533), 0.0);
	let glwe_noise_distribution =
	    Gaussian::from_dispersion_parameter(StandardDev(0.00000000000000029403601535432533), 0.0);
	let pbs_base_log = DecompositionBaseLog(23);
	let pbs_level = DecompositionLevelCount(1);
	let ciphertext_modulus = CiphertextModulus::new_native();

	let ksk_decomp_base_log = DecompositionBaseLog(3);
	let ksk_decomp_level_count = DecompositionLevelCount(5);

	// Request the best seeder possible, starting with hardware entropy sources and falling back to
	// /dev/random on Unix systems if enabled via cargo features
	let mut boxed_seeder = new_seeder();
	// Get a mutable reference to the seeder as a trait object from the Box returned by new_seeder
	let seeder = boxed_seeder.as_mut();

	// Create a generator which uses a CSPRNG to generate secret keys
	let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
	let mut ksk_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

	// Create a generator which uses two CSPRNGs to generate public masks and secret encryption
	// noise
	let mut encryption_generator =
	    EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);

	println!("Generating keys...");

	// Generate an LweSecretKey with binary coefficients
	let small_lwe_sk =
	    LweSecretKey::generate_new_binary(small_lwe_dimension, &mut secret_generator);
	println!("Creating LWEPublicKey...");
	let zero_encryption_count =
	    LwePublicKeyZeroEncryptionCount(small_lwe_dimension.to_lwe_size().0 * 64 + 128);
	let mut now = Instant::now();
	let small_lwe_pk = allocate_and_generate_new_lwe_public_key(
	    &small_lwe_sk,
	    zero_encryption_count,
	    ksk_noise_distribution,
	    ciphertext_modulus,
	    &mut encryption_generator,
	);
	let pk_gen_time = now.elapsed();
	println!("Creating LWEPublicKey took {:?}", pk_gen_time);

	// Generate a GlweSecretKey with binary coefficients
	let glwe_sk =
	    GlweSecretKey::generate_new_binary(glwe_dimension, polynomial_size, &mut secret_generator);

	// Create a copy of the GlweSecretKey re-interpreted as an LweSecretKey
	let big_lwe_sk = glwe_sk.clone().into_lwe_secret_key();
	println!("big_lwe_sk dimension: {:?}", big_lwe_sk.lwe_dimension());

	now = Instant::now();
	println!("Creating key switching key with public key...");
	// Create keyswitch key to switch from big_lwe_sk to small_lwe_sk
	// let ksk = allocate_and_generate_new_lwe_keyswitch_key(
	// let ksk = allocate_and_generate_new_lwe_keyswitch_key_with_public_key(
	let (ksk, ksk_mask_vector, msg_vector) = allocate_and_generate_new_lwe_keyswitch_key_with_public_key_ret_mask(
	    &big_lwe_sk,
	    // &small_lwe_sk,
	    &small_lwe_pk,
	    ksk_decomp_base_log,
	    ksk_decomp_level_count,
	    // lwe_noise_distribution,
	    ciphertext_modulus,
	    &mut ksk_generator,
	);
	let ksk_gen_time = now.elapsed();
	println!("Creating key switching key took {:?}", ksk_gen_time);

	// Generate the seeded bootstrapping key to show how to handle entity decompression,
	// we use the parallel variant for performance reason
	let std_bootstrapping_key = par_allocate_and_generate_new_seeded_lwe_bootstrap_key(
	    &small_lwe_sk,
	    &glwe_sk,
	    pbs_base_log,
	    pbs_level,
	    glwe_noise_distribution,
	    ciphertext_modulus,
	    seeder,
	);

	// We decompress the bootstrapping key
	let std_bootstrapping_key: LweBootstrapKeyOwned<u64> =
	    std_bootstrapping_key.decompress_into_lwe_bootstrap_key();

	// Create the empty bootstrapping key in the Fourier domain
	let mut fourier_bsk = FourierLweBootstrapKey::new(
	    std_bootstrapping_key.input_lwe_dimension(),
	    std_bootstrapping_key.glwe_size(),
	    std_bootstrapping_key.polynomial_size(),
	    std_bootstrapping_key.decomposition_base_log(),
	    std_bootstrapping_key.decomposition_level_count(),
	);

	// Use the conversion function (a memory optimized version also exists but is more complicated
	// to use) to convert the standard bootstrapping key to the Fourier domain
	convert_standard_lwe_bootstrap_key_to_fourier(&std_bootstrapping_key, &mut fourier_bsk);
	// We don't need the standard bootstrapping key anymore
	drop(std_bootstrapping_key);

	// Our 4 bits message space
	// let message_modulus = 1u64 << 4;
	let message_modulus = 1u64 << MSG_BITS;

    for msg in 0..2u64.pow(MSG_BITS) {
		// Our input message
		let input_message = msg;
		// let input_message = 3u64;

		// Delta used to encode 4 bits of message + a bit of padding on u64
		let delta = (1_u64 << 63) / message_modulus;
		// let delta = (1_u64 << 62) / message_modulus;

		// Apply our encoding
		let plaintext = Plaintext(input_message * delta);

		// Allocate a new LweCiphertext and encrypt our plaintext
		let lwe_ciphertext_in: LweCiphertextOwned<u64> = allocate_and_encrypt_new_lwe_ciphertext(
		    &small_lwe_sk,
		    plaintext,
		    lwe_noise_distribution,
		    ciphertext_modulus,
		    &mut encryption_generator,
		);

		// Now we will use a PBS to compute a multiplication by 2, it is NOT the recommended way of
		// doing this operation in terms of performance as it's much more costly than a multiplication
		// with a cleartext, however it resets the noise in a ciphertext to a nominal level and allows
		// to evaluate arbitrary functions so depending on your use case it can be a better fit.

		// Generate the accumulator for our multiplication by 2 using a simple closure
		let multiplier = 2u64;
		let accumulator: GlweCiphertextOwned<u64> = generate_programmable_bootstrap_glwe_lut(
		    polynomial_size,
		    glwe_dimension.to_glwe_size(),
		    message_modulus as usize,
		    ciphertext_modulus,
		    delta,
		    |x: u64| multiplier * x,
		);
		// let expected_output_message = (multiplier * input_message) % message_modulus;
		let expected_output_message = multiplier * input_message;
		let expected_plaintext = Plaintext(expected_output_message * delta);

		// Allocate the LweCiphertext to store the result of the PBS
		let mut pbs_multiplication_ct = LweCiphertext::new(
		    0u64,
		    big_lwe_sk.lwe_dimension().to_lwe_size(),
		    ciphertext_modulus,
		);
		println!("Computing PBS...");
		programmable_bootstrap_lwe_ciphertext(
		    &lwe_ciphertext_in,
		    &mut pbs_multiplication_ct,
		    &accumulator,
		    &fourier_bsk,
		);

		// Allocate the LWeCiphertext to store the result of the key switch
		let mut key_switch_ct = LweCiphertext::new(
		    0u64,
		    small_lwe_sk.lwe_dimension().to_lwe_size(),
		    ciphertext_modulus,
		);
		println!("Key switching...");
		keyswitch_lwe_ciphertext(&ksk, &pbs_multiplication_ct, &mut key_switch_ct);
		let (key_switch_mask, noisy_message) = keyswitch_lwe_ciphertext_ret_mask(&ksk, &pbs_multiplication_ct, &mut key_switch_ct, &ksk_mask_vector, &msg_vector);

		// Test if deterministic encryption matches for key_switch_ct
		let mut key_switch_ct_deterministic = LweCiphertext::new(
		    0u64,
		    small_lwe_sk.lwe_dimension().to_lwe_size(),
		    ciphertext_modulus,
		);
		encrypt_lwe_ciphertext_with_public_key_deterministic(
		    &small_lwe_pk,
		    &mut key_switch_ct_deterministic,
		    noisy_message,
		    key_switch_mask.binary_random_vector,
		);
        let mut diff_plaintext = expected_plaintext.0;
        diff_plaintext = diff_plaintext.wrapping_sub(noisy_message.0);
        println!("1: expected_plaintext: {:?}, noisy_message: {:?}, diff: {:?}", expected_plaintext, noisy_message, diff_plaintext);
        println!("2: expected_plaintext: {:?}, noisy_message: {:?}, diff: {:?}", expected_plaintext.0 / delta, noisy_message.0 / delta, diff_plaintext / delta);
        assert_eq!(key_switch_ct, key_switch_ct_deterministic);
		println!("Deterministic programmable bootstrapping: correct");

		// Decrypt the PBS multiplication result
		// let pbs_multiplication_plaintext: Plaintext<u64> =
		//     decrypt_lwe_ciphertext(&big_lwe_sk, &pbs_multiplication_ct);
		let key_switch_plaintext = decrypt_lwe_ciphertext(&small_lwe_sk, &key_switch_ct);

		// Create a SignedDecomposer to perform the rounding of the decrypted plaintext
		// We pass a DecompositionBaseLog of 5 and a DecompositionLevelCount of 1 indicating we want to
		// round the 5 MSB, 1 bit of padding plus our 4 bits of message
		let signed_decomposer =
		    SignedDecomposer::new(DecompositionBaseLog(5), DecompositionLevelCount(1));

		// Round and remove our encoding
		let key_switch_result: u64 =
		    signed_decomposer.closest_representable(key_switch_plaintext.0) / delta;
		// let pbs_multiplication_result: u64 =
		//     signed_decomposer.closest_representable(pbs_multiplication_plaintext.0) / delta;

		println!("Checking result...");
		assert_eq!(expected_output_message, key_switch_result);
		// assert_eq!(6, pbs_multiplication_result);
		println!(
		    "Multiplication via PBS, followed by key switch result is correct! Expected {expected_output_message}, got {key_switch_result}"
		    // "Multiplication via PBS, followed by key switch result is correct! Expected 6, got {pbs_multiplication_result}"
		);
	}
}

fn test_save_on_file_keys(
	client_key_path: &String,
    server_key_path: &String,
    output_lwe_path: &String,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = ConfigBuilder::with_custom_parameters(BLOCK_PARAMS).build();
    let (client_key, server_key) = generate_keys(config);

    let (integer_ck, _, _, _) = client_key.clone().into_raw_parts();
    let shortint_ck = integer_ck.into_raw_parts();
    assert!(BLOCK_PARAMS.encryption_key_choice == EncryptionKeyChoice::Big);
    let (glwe_secret_key, _, parameters) = shortint_ck.into_raw_parts();
    let lwe_secret_key = glwe_secret_key.into_lwe_secret_key();

    println!("client_key: {:?}", client_key);

    // let client_key_path = dir_path.clone().push_str("/client_key");
    // let server_key_path = dir_path.clone().push_str("/server_key");
    // let output_lwe_path = dir_path.clone().push_str("/output_key");
    write_keys(
        client_key_path,
        server_key_path,
        output_lwe_path,
        Some(client_key),
        Some(server_key),
        Some(lwe_secret_key),
    )?;
    Ok(())

}

fn test_save_on_file_encrypt(
    // msg: u8,
    msg: u64,
    client_key_path: &String,
    ciphertext_path: &String,
) -> Result<(), Box<dyn std::error::Error>> {

    let client_key = load_client_key(client_key_path);
    let (integer_ck, _, _, _) = client_key.clone().into_raw_parts();
    let shortint_ck = integer_ck.into_raw_parts();
    assert!(BLOCK_PARAMS.encryption_key_choice == EncryptionKeyChoice::Big);
    let (_, lwe_secret_key, parameters) = shortint_ck.into_raw_parts();
    let lwe_dimension = parameters.lwe_dimension();
    let lwe_noise_distribution = parameters.lwe_noise_distribution();
    let message_modulus = parameters.message_modulus();
    let encoding :u32 = u64::BITS - (message_modulus.0 as u32);

    // let ct = FheUint8::encrypt(msg, &client_key);
    // serialize_fheuint8(ct, ciphertext_path);

    // Create the PRNG
    let mut seeder = new_seeder();
    let seeder = seeder.as_mut();
    let mut encryption_generator =
        EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);

    // Create the plaintext
    let plaintext = Plaintext(msg << encoding);

    // Create a new LweCiphertext
    let mut ct = LweCiphertext::new(
        0u64,
        lwe_dimension.to_lwe_size(),
        CiphertextModulus::new_native(),
    );

    encrypt_lwe_ciphertext(
        &lwe_secret_key,
        &mut ct,
        plaintext,
        lwe_noise_distribution,
        &mut encryption_generator,
    );

    serialize_lwe_ciphertext(&ct, ciphertext_path);

    Ok(())
}

fn test_load_from_file_decrypt(
    client_key_path: &String,
    ciphertext_path: &String,
) -> Result<(), Box<dyn std::error::Error>> {
    
    let client_key = load_client_key(client_key_path);
    let (integer_ck, _, _, _) = client_key.clone().into_raw_parts();
    let shortint_ck = integer_ck.into_raw_parts();
    assert!(BLOCK_PARAMS.encryption_key_choice == EncryptionKeyChoice::Big);
    let (_, lwe_secret_key, parameters) = shortint_ck.into_raw_parts();
    let message_modulus = parameters.message_modulus();
    let encoding :u32 = u64::BITS - (message_modulus.0 as u32);

    // let fheuint = deserialize_fheuint8(ciphertext_path);
    // let result: u8 = fheuint.decrypt(&client_key);

    // deserialize_lwe_ciphertext::<u64>(ciphertext_path);
    let lwe = deserialize_lwe_ciphertext(ciphertext_path);

    let decrypted_plaintext = decrypt_lwe_ciphertext(&lwe_secret_key, &lwe);

    // Round and remove encoding
    // First create a decomposer working on the high 4 bits corresponding to our
    // encoding.
    let decomposer = SignedDecomposer::new(
        DecompositionBaseLog(message_modulus.0 as usize),
        DecompositionLevelCount(1),
    );

    let rounded = decomposer.closest_representable(decrypted_plaintext.0);

    // Remove the encoding
    let cleartext = rounded >> encoding;

    println!("cleartext: {}", cleartext);

    Ok(())
}

fn main() {
	let args: Vec<String> = std::env::args().collect();
	let argument = &args[1];
    // for argument in std::env::args() {
    if argument == "sk_lwe_enc" {
        println!("Testing encrypt_lwe_ciphertext");
        test_sk_lwe_enc();
        println!();
    }
    if argument == "sk_lwe_enc_det" {
        println!("Testing encrypt_lwe_ciphertext_ret_noise");
        test_sk_lwe_enc_det();
        println!();
    }
    if argument == "sk_lwe_add" {
        println!("Testing sk LWE hommorphic addition");
        test_sk_lwe_add();
        println!();
    }
    if argument == "sk_lwe_mult_const" {
        println!("Testing sk LWE hommorphic multiplication with constant");
        test_sk_lwe_mult_const();
        println!();
    }
    if argument == "pk_lwe_enc" {
        println!("Testing encrypt_lwe_ciphertext_with_public_key");
        test_pk_lwe_enc();
        println!();
    }
    if argument == "pk_lwe_enc_det" {
        println!("Testing encrypt_lwe_ciphertext_with_public_key_ret_mask");
        test_pk_lwe_enc_det();
        println!();
    }
    if argument == "pk_lwe_add" {
        println!("Testing pk hommorphic addition");
        test_pk_lwe_add();
        println!();
    }
    if argument == "pk_lwe_mult_const" {
        println!("Testing pk hommorphic multiplication with constant");
        test_pk_lwe_mult_const();
        println!();
    }
    if argument == "sk_glwe_enc" {
        println!("Testing encrypt_glwe_ciphertext");
        test_sk_glwe_enc();
        println!();
    }
    if argument == "sk_glwe_enc_det" {
        println!("Testing encrypt_glwe_ciphertext_ret_noise");
        test_sk_glwe_enc_det();
        println!();
    }
    if argument == "sk_glwe_add" {
        println!("Testing sk GLWE hommorphic addition");
        test_sk_glwe_add();
        println!();
    }
    if argument == "sk_glwe_mult_const" {
        println!("Testing sk GLWE hommorphic multiplication with constant");
        test_sk_glwe_mult_const();
        println!();
    }
    if argument == "sk_ggsw_enc" {
        println!("Testing encrypt_constant_seeded_ggsw_ciphertext");
        test_sk_ggsw_enc();
        println!();
    }
    if argument == "sk_ggsw_enc_det" {
        println!("Testing encrypt_constant_seeded_ggsw_ciphertext");
        test_sk_ggsw_enc_det();
        println!();
    }
    if argument == "sk_ggsw_par_enc" {
        println!("Testing par_encrypt_constant_seeded_ggsw_ciphertext");
        test_sk_ggsw_par_enc();
        println!();
    }
    if argument == "sk_ggsw_par_enc_det" {
        println!("Testing par_encrypt_constant_seeded_ggsw_ciphertext");
        test_sk_ggsw_par_enc_det();
        println!();
    }
    if argument == "blind_rotate" {
        println!("Testing blind rotation");
        test_blind_rotate();
        println!();
    }
    if argument == "blind_rotate_det" {
        println!("Testing blind rotation deterministic");
        test_blind_rotate_det();
        println!();
    }
    if argument == "sk_key_switch" {
        println!("Testing sk key switching");
        test_sk_key_switch();
        println!();
    }
    if argument == "sk_key_switch_det" {
        println!("Testing sk key switching deterministic");
        test_sk_key_switch_det();
        println!();
    }
    if argument == "pk_key_switch" {
        println!("Testing pk key switching");
        let value1 = args[2].parse::<u64>().expect("Argument 1 must be a valid unsigned integer");
        let value2 = args[3].parse::<u64>().expect("Argument 2 must be a valid unsigned integer");
        test_pk_key_switch(value1, value2);
        println!();
    }
    if argument == "pk_key_switch_det" {
        println!("Testing pk key switching");
        // let value1 = args[2].parse::<u64>().expect("Argument 1 must be a valid unsigned integer");
        // let value2 = args[3].parse::<u64>().expect("Argument 2 must be a valid unsigned integer");
        // test_pk_key_switch(value1, value2);
        test_pk_key_switch_det();
        println!();
    }
    if argument == "sk_pbs" {
        println!("Testing sk programmable bootstrapping");
        let value = args[2].parse::<u64>().expect("Argument must be a valid unsigned integer");
        test_sk_pbs(value);
        println!();
    }
    if argument == "sk_pbs_full" {
        println!("Testing sk programmable bootstrapping fully: blind rotate, sample extract, key switch");
        test_sk_pbs_full();
        println!();
    }
    if argument == "sk_pbs_full_det" {
        println!("Testing sk deterministic programmable bootstrapping fully: blind rotate, sample extract, key switch");
        test_sk_pbs_full_det();
        println!();
    }
    if argument == "sk_pbs_det" {
        println!("Testing sk programmable bootstrapping deterministic");
        test_sk_pbs_det();
        println!();
    }
    if argument == "pk_pbs_full" {
        println!("Testing pk programmable bootstrapping");
        test_pk_pbs_full();
        println!();
    }
    if argument == "pk_pbs_full_det" {
        println!("Testing pk programmable bootstrapping deterministic");
        test_pk_pbs_full_det();
        println!();
    }
    if argument == "save_on_file_keys" {
        println!("Testing saving keys on file");
        let client_key_path = &args[2];
        let server_key_path = &args[3];
        let output_key_path = &args[4];
        test_save_on_file_keys(client_key_path, server_key_path, output_key_path);
        println!();
    }
    if argument == "save_on_file_encrypt" {
        println!("Testing saving ciphertext on file");
        // let value : &u8 = &args[2].parse::<u8>().expect("Argument must be a valid unsigned integer");
        let value : &u64 = &args[2].parse::<u64>().expect("Argument must be a valid unsigned integer");
        let client_key_path = &args[3];
        let ciphertext_path = &args[4];
        test_save_on_file_encrypt(*value, client_key_path, ciphertext_path);
        println!();
    }
    if argument == "load_from_file_decrypt" {
        println!("Testing loading ciphertext from file and decrpytion");
        let client_key_path = &args[2];
        let ciphertext_path = &args[3];
        test_load_from_file_decrypt(client_key_path, ciphertext_path);
        println!();
    }
    // }
}
