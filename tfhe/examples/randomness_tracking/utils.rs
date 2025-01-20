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

use bincode;
use clap::{Arg, ArgAction, Command};
use core::panic;
use std::fs;
use std::io::Cursor;
use std::path::Path;
use tfhe::core_crypto::prelude::LweSecretKey;
use tfhe::shortint::{ClassicPBSParameters, EncryptionKeyChoice};
use tfhe::{generate_keys, set_server_key, ClientKey, FheUint8, ServerKey};
use tfhe::{prelude::*, ConfigBuilder};
use serde::{Deserialize, Serialize};
use serde::de::DeserializeOwned;

pub fn write_keys(
    client_key_path: &String,
    server_key_path: &String,
    output_lwe_path: &String,
    client_key: Option<ClientKey>,
    server_key: Option<ServerKey>,
    lwe_secret_key: Option<LweSecretKey<Vec<u64>>>,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(ck) = client_key {
        let mut serialized_client_key = Vec::new();
        bincode::serialize_into(&mut serialized_client_key, &ck)?;
        let path_client_key: &Path = Path::new(client_key_path);
        fs::write(path_client_key, serialized_client_key).unwrap();
    }

    if let Some(sk) = server_key {
        let mut serialized_server_key = Vec::new();
        bincode::serialize_into(&mut serialized_server_key, &sk)?;
        let path_server_key: &Path = Path::new(server_key_path);
        fs::write(path_server_key, serialized_server_key).unwrap();
    }

    if let Some(lwe_sk) = lwe_secret_key {
        let mut serialized_lwe_key = Vec::new();
        bincode::serialize_into(&mut serialized_lwe_key, &lwe_sk)?;
        let path_lwe_key: &Path = Path::new(output_lwe_path);
        fs::write(path_lwe_key, serialized_lwe_key).unwrap();
    }

    Ok(())
}

pub fn load_client_key(client_path: &String) -> ClientKey {
    let path_key: &Path = Path::new(client_path);
    let serialized_key = fs::read(path_key).unwrap();
    let mut serialized_data = Cursor::new(serialized_key);
    let client_key: ClientKey = bincode::deserialize_from(&mut serialized_data).unwrap();
    client_key
}

pub fn load_server_key(server_path: &String) -> ServerKey {
    let path_key: &Path = Path::new(server_path);
    let serialized_key = fs::read(path_key).unwrap();
    let mut serialized_data = Cursor::new(serialized_key);
    let server_key: ServerKey = bincode::deserialize_from(&mut serialized_data).unwrap();
    server_key
}

pub fn serialize_fheuint8(fheuint: FheUint8, ciphertext_path: &String) {
    let mut serialized_ct = Vec::new();
    bincode::serialize_into(&mut serialized_ct, &fheuint).unwrap();
    let path_ct: &Path = Path::new(ciphertext_path);
    fs::write(path_ct, serialized_ct).unwrap();
}

pub fn deserialize_fheuint8(path: &String) -> FheUint8 {
    let path_fheuint: &Path = Path::new(path);
    let serialized_fheuint = fs::read(path_fheuint).unwrap();
    let mut serialized_data = Cursor::new(serialized_fheuint);
    bincode::deserialize_from(&mut serialized_data).unwrap()
}


pub fn serialize_lwe_ciphertext<
    Scalar, 
    // C,
    // OutputCont, 
    // NoiseDistribution,
> (
    // lwe_ciphertext: &LweCiphertext<OutputCont>, 
    lwe_ciphertext: &LweCiphertext<Vec<Scalar>>, 
    // lwe_ciphertext: &LweCiphertext<C>, 
    ciphertext_path: &String
) where 
    // Scalar: Encryptable<Uniform, NoiseDistribution> + Serialize,
    Scalar: UnsignedInteger + Serialize,
    // NoiseDistribution: Distribution,
    // OutputCont: Container<Element = Scalar>,
{
    let mut serialized_ct = Vec::new();
    // serialized_ct = lwe_ciphertext.as_ref().to_vec();
    bincode::serialize_into(&mut serialized_ct, &lwe_ciphertext).unwrap();
    let path_ct: &Path = Path::new(ciphertext_path);
    fs::write(path_ct, serialized_ct).unwrap();
}

pub fn deserialize_lwe_ciphertext< 
    // 'a, 
    Scalar, 
    // Cont,
> (
    path: &String
// ) 
) -> LweCiphertext<Vec<Scalar>> 
// ) -> &LweCiphertext<Cont> 
where 
    // Cont: Container<Element = Scalar>
    Scalar: UnsignedInteger + DeserializeOwned,
    // Scalar: UnsignedInteger + Deserialize,
    // Scalar: UnsignedInteger + for<'a> Deserialize<'a>,
    // for<'a> Scalar: UnsignedInteger + Deserialize<'a>,
    // Scalar: UnsignedInteger + Deserialize<'a>,
{
    let path_lwe_ciphertext: &Path = Path::new(path);
    let serialized_lwe_ciphertext = fs::read(path_lwe_ciphertext).unwrap();
    let mut serialized_data = Cursor::new(serialized_lwe_ciphertext);
    // println!("serialized_data: {:?}", serialized_data);
    let ct : LweCiphertext<Vec<Scalar>> = bincode::deserialize_from(&mut serialized_data).unwrap();
    ct
}

pub fn load_lwe_sk(lwe_sk_path: &String) -> LweSecretKey<Vec<u64>> {
    let path_sk: &Path = Path::new(lwe_sk_path);
    let serialized_sk = fs::read(path_sk).unwrap();
    let mut serialized_data = Cursor::new(serialized_sk);
    bincode::deserialize_from(&mut serialized_data).unwrap()
}













