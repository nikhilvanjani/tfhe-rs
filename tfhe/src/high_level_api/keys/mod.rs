mod client;
mod public;
mod server;

mod inner;
mod key_switching_key;

use crate::high_level_api::config::Config;
pub use client::ClientKey;
pub(crate) use inner::CompactPrivateKey;
pub use key_switching_key::KeySwitchingKey;
pub use public::{CompactPublicKey, CompressedCompactPublicKey, CompressedPublicKey, PublicKey};
#[cfg(feature = "gpu")]
pub use server::CudaServerKey;
pub(crate) use server::InternalServerKey;
pub use server::{CompressedServerKey, ServerKey};

pub(in crate::high_level_api) use inner::{
    IntegerClientKey, IntegerCompactPublicKey, IntegerCompressedCompactPublicKey,
    IntegerCompressedServerKey, IntegerConfig, IntegerServerKey,
};
use crate::core_crypto::prelude::{LweBody, PlaintextListOwned, LwePublicKeyZeroEncryptionCount, PublicKeyRandomVectors, LwePublicKeyOwned};

/// Generates keys using the provided config.
///
/// # Example
///
/// ```rust
/// use tfhe::{generate_keys, ConfigBuilder};
///
/// let config = ConfigBuilder::default().build();
/// let (client_key, server_key) = generate_keys(config);
/// ```
pub fn generate_keys<C: Into<Config>>(config: C) -> (ClientKey, ServerKey) {
    let client_kc = ClientKey::generate(config);
    let server_kc = client_kc.generate_server_key();

    (client_kc, server_kc)
}

pub fn generate_keys_with_public_key_ret_noise<C: Into<Config>>(config: C) -> (ClientKey, ServerKey, Vec<Vec<PublicKeyRandomVectors<u64>>>, Vec<PlaintextListOwned<u64>>, LwePublicKeyOwned<u64>) {
    let client_kc = ClientKey::generate(config);
    let (server_kc, ksk_mask_vector, msg_vector, server_pk) = client_kc.generate_server_key_with_public_key_ret_noise();

    (client_kc, server_kc, ksk_mask_vector, msg_vector, server_pk)
}