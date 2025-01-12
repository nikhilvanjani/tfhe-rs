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
// use std::time::Instant;

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

const NB_TESTS: usize = 1;

mod deterministic_encryption;
mod deterministic_lin_algebra;


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

fn test_sk_lwe_enc_ret_mask_and_noise() {
	println!("Testing encrypt_lwe_ciphertext_ret_mask_and_noise");
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

            // let SecretKeyRandomVectors {
            // 	mask,
            // 	noise
            // } = encrypt_lwe_ciphertext_ret_mask_and_noise(
            let noise = encrypt_lwe_ciphertext_ret_mask_and_noise(
                &lwe_secret_key,
                &mut lwe,
                plaintext,
                lwe_noise_distribution,
                &mut encryption_generator,
            );
            let mask = lwe.get_mask();
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
                noise,
            );

			assert!(lwe == lwe2);
			println!("Deterministic encryption: correct");

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

    const MSG_BITS: u32 = 4;

    for _ in 0..NB_TESTS {
        for msg in 0..2u128.pow(MSG_BITS) {
     	   for msg2 in 0..2u128.pow(MSG_BITS) {
	            // Create the LweSecretKey
	            let lwe_secret_key = allocate_and_generate_new_binary_lwe_secret_key(
	                lwe_dimension,
	                &mut secret_generator,
	            );

	            // Create the plaintext
	            const ENCODING: u32 = u128::BITS - MSG_BITS;
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

	            let noise_a = encrypt_lwe_ciphertext_ret_mask_and_noise(
	                &lwe_secret_key,
	                &mut a,
	                plaintext_a,
	                lwe_noise_distribution,
	                &mut encryption_generator,
	            );
	            let mask_a = a.get_mask();

	            let noise_b = encrypt_lwe_ciphertext_ret_mask_and_noise(
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
	                &LweMask::from_container(mask_c.as_ref(), mask_c.ciphertext_modulus()),
	                noise_c,
	            );

				assert!(c == h_c);
				println!("Randomness in homomorphic addition: correct");

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

    const MSG_BITS: u32 = 4;

    for _ in 0..NB_TESTS {
        for msg in 0..2u128.pow(MSG_BITS) {
     	   for msg2 in 0..2u128.pow(MSG_BITS) {
	            // Create the LweSecretKey
	            let lwe_secret_key = allocate_and_generate_new_binary_lwe_secret_key(
	                lwe_dimension,
	                &mut secret_generator,
	            );

	            // Create the plaintext
	            const ENCODING: u32 = u128::BITS - MSG_BITS;
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

	            let noise_a = encrypt_lwe_ciphertext_ret_mask_and_noise(
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
	                &LweMask::from_container(mask_c.as_ref(), mask_c.ciphertext_modulus()),
	                noise_c,
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

fn test_pk_lwe_enc_ret_mask() {
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
	encrypt_lwe_ciphertext_with_public_key_and_mask(
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
	encrypt_lwe_ciphertext_with_public_key_and_mask(
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

fn test_pbs() {
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

fn test_pbs_det() {
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

fn main() {
    for argument in std::env::args() {
        if argument == "sk_lwe_enc" {
            println!("Testing encrypt_lwe_ciphertext");
            test_sk_lwe_enc();
            println!();
        }
        if argument == "sk_lwe_enc_det" {
            println!("Testing encrypt_lwe_ciphertext_ret_mask_and_noise");
            test_sk_lwe_enc_ret_mask_and_noise();
            println!();
        }
        if argument == "sk_lwe_enc_add" {
            println!("Testing sk hommorphic addition");
            test_sk_lwe_add();
            println!();
        }
        if argument == "sk_lwe_enc_mult_const" {
            println!("Testing sk hommorphic multiplication with constant");
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
            test_pk_lwe_enc_ret_mask();
            println!();
        }
        if argument == "pk_lwe_enc_add" {
            println!("Testing pk hommorphic addition");
            test_pk_lwe_add();
            println!();
        }
        if argument == "pk_lwe_enc_mult_const" {
            println!("Testing pk hommorphic multiplication with constant");
            test_pk_lwe_mult_const();
            println!();
        }

        if argument == "lwe_pbs" {
            println!("Testing programmable bootstrapping");
            test_pbs();
            println!();
        }
        if argument == "lwe_pbs_det" {
            println!("Testing programmable bootstrapping");
            test_pbs_det();
            println!();
        }

    }
}
