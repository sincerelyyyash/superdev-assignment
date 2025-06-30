use solana_sdk::{
    pubkey::Pubkey,
    signature::{Keypair, Signature},
};
use std::str::FromStr;
use base64::{Engine as _, engine::general_purpose};

pub fn validate_pubkey(pubkey_str: &str) -> Result<Pubkey, String> {
    match Pubkey::from_str(pubkey_str) {
        Ok(pk) => Ok(pk),
        Err(_) => Err("Invalid public key format".to_string())
    }
}

pub fn validate_keypair_from_base58(secret_str: &str) -> Result<Keypair, String> {
    let decoded_bytes = bs58::decode(secret_str)
        .into_vec()
        .map_err(|_| "Invalid base58 secret key")?;
    
    if decoded_bytes.len() != 64 {
        return Err("Invalid secret key length".to_string());
    }
    
    let keypair_result = Keypair::from_bytes(&decoded_bytes);
    match keypair_result {
        Ok(kp) => Ok(kp),
        Err(_) => Err("Invalid keypair bytes".to_string())
    }
}

pub fn validate_signature_from_base64(sig_str: &str) -> Result<Signature, String> {
    let decoded_sig = general_purpose::STANDARD.decode(sig_str);
    
    if let Err(_) = decoded_sig {
        return Err("Invalid base64 signature".to_string());
    }
    
    let sig_bytes = decoded_sig.unwrap();
    Signature::try_from(sig_bytes.as_slice())
        .map_err(|_| "Invalid signature format".to_string())
}