//! Keeper's wire crypto. "v1" is AES-256-CBC with the IV prepended, "v2" is AES-256-GCM with
//! a 12-byte nonce prepended and the tag appended; EC is ECIES over P-256 using SHA-256 of the
//! raw ECDH secret as a v2 key.

use aes::Aes256;
#[cfg(test)]
use aes::cipher::BlockEncryptMut;
use aes::cipher::block_padding::{NoPadding, Pkcs7};
use aes::cipher::{BlockDecryptMut, KeyIvInit};
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use hmac::{Hmac, Mac};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{PublicKey, SecretKey};
use rand::RngCore;
use rand::rngs::OsRng;
use rsa::pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey};
use rsa::pkcs8::DecodePrivateKey;
use rsa::traits::PublicKeyParts;
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256, Sha512};

use crate::prelude::*;

const EC_PUBLIC_KEY_LEN: usize = 65;

pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    OsRng.fill_bytes(&mut buf);
    buf
}

fn crypto_err(what: &str) -> Error {
    Error::Crypto(what.to_owned())
}

// The CLI is read-only, so CBC encryption only builds test fixtures.
#[cfg(test)]
pub fn encrypt_aes_v1(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    encrypt_cbc::<Pkcs7>(data, key, &random_bytes(16), data.len() + 16)
}

/// Unpadded CBC, used only for the 64-byte doubled data key inside encryption params.
#[cfg(test)]
pub fn encrypt_aes_v1_nopad(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    encrypt_cbc::<NoPadding>(data, key, &random_bytes(16), data.len())
}

#[cfg(test)]
fn encrypt_cbc<P: aes::cipher::block_padding::Padding<aes::cipher::consts::U16>>(
    data: &[u8],
    key: &[u8],
    iv: &[u8],
    capacity: usize,
) -> Result<Vec<u8>> {
    let enc = cbc::Encryptor::<Aes256>::new_from_slices(key, iv).map_err(|_| crypto_err("bad AES key length"))?;
    let mut buf = vec![0u8; capacity];
    buf[..data.len()].copy_from_slice(data);
    let len = enc
        .encrypt_padded_mut::<P>(&mut buf, data.len())
        .map_err(|_| crypto_err("AES-CBC input is not block aligned"))?
        .len();
    buf.truncate(len);
    let mut out = iv.to_vec();
    out.extend_from_slice(&buf);
    Ok(out)
}

pub fn decrypt_aes_v1(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    decrypt_cbc::<Pkcs7>(data, key)
}

pub fn decrypt_aes_v1_nopad(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    decrypt_cbc::<NoPadding>(data, key)
}

fn decrypt_cbc<P: aes::cipher::block_padding::Padding<aes::cipher::consts::U16>>(
    data: &[u8],
    key: &[u8],
) -> Result<Vec<u8>> {
    if data.len() < 32 {
        return Err(crypto_err("AES-CBC ciphertext too short"));
    }
    let (iv, body) = data.split_at(16);
    let dec = cbc::Decryptor::<Aes256>::new_from_slices(key, iv).map_err(|_| crypto_err("bad AES key length"))?;
    let mut buf = body.to_vec();
    let len = dec
        .decrypt_padded_mut::<P>(&mut buf)
        .map_err(|_| crypto_err("AES-CBC decryption failed"))?
        .len();
    buf.truncate(len);
    Ok(buf)
}

pub fn encrypt_aes_v2(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| crypto_err("bad AES key length"))?;
    let nonce = random_bytes(12);
    let sealed = cipher
        .encrypt(Nonce::from_slice(&nonce), data)
        .map_err(|_| crypto_err("AES-GCM encryption failed"))?;
    let mut out = nonce;
    out.extend_from_slice(&sealed);
    Ok(out)
}

pub fn decrypt_aes_v2(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 12 + 16 {
        return Err(crypto_err("AES-GCM ciphertext too short"));
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| crypto_err("bad AES key length"))?;
    let (nonce, body) = data.split_at(12);
    cipher
        .decrypt(Nonce::from_slice(nonce), body)
        .map_err(|_| crypto_err("AES-GCM decryption failed"))
}

pub fn generate_ec_key() -> SecretKey {
    SecretKey::random(&mut OsRng)
}

pub fn load_ec_private_key(bytes: &[u8]) -> Result<SecretKey> {
    SecretKey::from_slice(bytes).map_err(|_| crypto_err("invalid EC private key"))
}

pub fn load_ec_public_key(bytes: &[u8]) -> Result<PublicKey> {
    PublicKey::from_sec1_bytes(bytes).map_err(|_| crypto_err("invalid EC public key"))
}

pub fn unload_ec_public_key(key: &PublicKey) -> Vec<u8> {
    key.to_encoded_point(false).as_bytes().to_vec()
}

fn ecdh_key(secret: &SecretKey, public: &PublicKey) -> Vec<u8> {
    let shared = p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), public.as_affine());
    Sha256::digest(shared.raw_secret_bytes()).to_vec()
}

pub fn encrypt_ec(data: &[u8], public: &PublicKey) -> Result<Vec<u8>> {
    let ephemeral = generate_ec_key();
    let mut out = unload_ec_public_key(&ephemeral.public_key());
    out.extend(encrypt_aes_v2(data, &ecdh_key(&ephemeral, public))?);
    Ok(out)
}

pub fn decrypt_ec(data: &[u8], private: &SecretKey) -> Result<Vec<u8>> {
    if data.len() <= EC_PUBLIC_KEY_LEN {
        return Err(crypto_err("EC ciphertext too short"));
    }
    let (ephemeral, body) = data.split_at(EC_PUBLIC_KEY_LEN);
    decrypt_aes_v2(body, &ecdh_key(private, &load_ec_public_key(ephemeral)?))
}

pub fn load_rsa_private_key(der: &[u8]) -> Result<RsaPrivateKey> {
    RsaPrivateKey::from_pkcs1_der(der)
        .or_else(|_| RsaPrivateKey::from_pkcs8_der(der))
        .map_err(|_| crypto_err("invalid RSA private key"))
}

pub fn load_rsa_public_key(der: &[u8]) -> Result<RsaPublicKey> {
    RsaPublicKey::from_pkcs1_der(der).map_err(|_| crypto_err("invalid RSA public key"))
}

pub fn encrypt_rsa(data: &[u8], key: &RsaPublicKey) -> Result<Vec<u8>> {
    key.encrypt(&mut OsRng, Pkcs1v15Encrypt, data)
        .map_err(|_| crypto_err("RSA encryption failed"))
}

pub fn decrypt_rsa(data: &[u8], key: &RsaPrivateKey) -> Result<Vec<u8>> {
    // Some Keeper clients strip leading zero bytes from RSA ciphertext.
    let size = key.size();
    let padded;
    let data = if data.len() < size {
        padded = [vec![0u8; size - data.len()], data.to_vec()].concat();
        &padded
    } else {
        data
    };
    key.decrypt(Pkcs1v15Encrypt, data)
        .map_err(|_| crypto_err("RSA decryption failed"))
}

pub fn derive_key_v1(password: &str, salt: &[u8], iterations: u32) -> [u8; 32] {
    pbkdf2::pbkdf2_hmac_array::<Sha256, 32>(password.as_bytes(), salt, iterations)
}

pub fn derive_keyhash_v1(password: &str, salt: &[u8], iterations: u32) -> Vec<u8> {
    Sha256::digest(derive_key_v1(password, salt, iterations)).to_vec()
}

/// Key derivation for "alternate" (SSO master password) logins.
pub fn derive_keyhash_v2(domain: &str, password: &str, salt: &[u8], iterations: u32) -> Vec<u8> {
    let derived = pbkdf2::pbkdf2_hmac_array::<Sha512, 64>(format!("{domain}{password}").as_bytes(), salt, iterations);
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&derived).expect("HMAC accepts any key length");
    mac.update(domain.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

/// Encryption params are `version(1) | iterations(3, BE) | salt(16) | CBC(data_key || data_key)`.
/// The doubled key is the only integrity check a wrong password gets.
pub fn decrypt_encryption_params(params: &[u8], password: &str) -> Result<Vec<u8>> {
    if params.len() != 100 {
        return Err(crypto_err("invalid encryption params length"));
    }
    let iterations = u32::from_be_bytes([0, params[1], params[2], params[3]]);
    let key = derive_key_v1(password, &params[4..20], iterations);
    let doubled = decrypt_aes_v1_nopad(&params[20..], &key)?;
    if doubled.len() != 64 || doubled[..32] != doubled[32..] {
        return Err(crypto_err("data key mirror check failed (wrong password?)"));
    }
    Ok(doubled[..32].to_vec())
}

#[cfg(test)]
pub fn create_encryption_params(password: &str, salt: &[u8], iterations: u32, data_key: &[u8]) -> Result<Vec<u8>> {
    let key = derive_key_v1(password, salt, iterations);
    let mut out = vec![1u8];
    out.extend_from_slice(&iterations.to_be_bytes()[1..]);
    out.extend_from_slice(salt);
    out.extend(encrypt_aes_v1_nopad(&[data_key, data_key].concat(), &key)?);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cbc_and_gcm_roundtrip_and_reject_wrong_key() {
        let key = random_bytes(32);
        let other = random_bytes(32);
        for msg in [&b""[..], b"x", &[7u8; 16], &[9u8; 33]] {
            let v1 = encrypt_aes_v1(msg, &key).unwrap();
            assert_eq!(v1.len() % 16, 0);
            assert_eq!(decrypt_aes_v1(&v1, &key).unwrap(), msg);
            let v2 = encrypt_aes_v2(msg, &key).unwrap();
            assert_eq!(v2.len(), 12 + msg.len() + 16);
            assert_eq!(decrypt_aes_v2(&v2, &key).unwrap(), msg);
            assert!(decrypt_aes_v2(&v2, &other).is_err());
        }
    }

    #[test]
    fn ec_roundtrip_through_serialized_keys() {
        let private = generate_ec_key();
        let public = load_ec_public_key(&unload_ec_public_key(&private.public_key())).unwrap();
        let sealed = encrypt_ec(b"transmission key", &public).unwrap();
        let reloaded = load_ec_private_key(&private.to_bytes()).unwrap();
        assert_eq!(decrypt_ec(&sealed, &reloaded).unwrap(), b"transmission key");
        assert!(decrypt_ec(&sealed, &generate_ec_key()).is_err());
    }

    #[test]
    fn pbkdf2_sha256_matches_published_vector() {
        // RFC 7914 §11 PBKDF2-HMAC-SHA256 vector (first 32 bytes of the 64-byte output).
        let key = derive_key_v1("passwd", b"salt", 1);
        assert_eq!(
            data_encoding::HEXLOWER.encode(&key),
            "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"
        );
    }

    #[test]
    fn encryption_params_recover_data_key_only_with_right_password() {
        let data_key = random_bytes(32);
        let params = create_encryption_params("hunter2", &random_bytes(16), 1000, &data_key).unwrap();
        assert_eq!(params.len(), 100);
        assert_eq!(decrypt_encryption_params(&params, "hunter2").unwrap(), data_key);
        assert!(decrypt_encryption_params(&params, "hunter3").is_err());
    }

    #[test]
    fn rsa_decrypt_tolerates_stripped_leading_zeros() {
        let private = RsaPrivateKey::new(&mut OsRng, 1024).unwrap();
        let public = RsaPublicKey::from(&private);
        let sealed = loop {
            let c = encrypt_rsa(b"record key", &public).unwrap();
            if c[0] == 0 {
                break c;
            }
        };
        assert_eq!(decrypt_rsa(&sealed[1..], &private).unwrap(), b"record key");
    }
}
