//! Keeper's wire crypto. "v1" is AES-256-CBC with the IV prepended, "v2" is AES-256-GCM with
//! a 12-byte nonce prepended and the tag appended; EC is ECIES over P-256 using SHA-256 of the
//! raw ECDH secret as a v2 key.

use aes::Aes256;
use aes::cipher::block_padding::NoPadding;
#[cfg(test)]
use aes::cipher::block_padding::Pkcs7;
use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use aes_gcm::aead::{Aead, AeadInPlace, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce, Tag};
use hmac::{Hmac, Mac};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use rand::RngCore;
use rand::rngs::OsRng;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::traits::PublicKeyParts;
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey};
use sha2::{Digest, Sha256, Sha512};

use crate::prelude::*;

const EC_PUBLIC_KEY_LEN: usize = 65;

pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    OsRng.fill_bytes(&mut buf);
    buf
}

/// A 256-bit AES key. Every symmetric key Keeper uses (data, record, folder, team, shared folder)
/// is one, so holding one of these means the length has already been checked.
#[derive(Clone, PartialEq, Eq)]
pub struct AesKey([u8; 32]);

impl AesKey {
    pub fn random() -> Self {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        Self(key)
    }
}

impl TryFrom<Vec<u8>> for AesKey {
    type Error = Error;

    fn try_from(bytes: Vec<u8>) -> Result<Self> {
        <[u8; 32]>::try_from(bytes.as_slice())
            .map(Self)
            .map_err(|_| Error::Crypto(format!("expected a 32-byte key, got {} bytes", bytes.len())))
    }
}

/// Every cipher function takes key bytes; deref lets `&AesKey` be passed straight through.
impl std::ops::Deref for AesKey {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for AesKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AesKey(..)")
    }
}

pub fn encrypt_cbc<P: aes::cipher::block_padding::Padding<aes::cipher::consts::U16>>(
    data: &[u8],
    key: &[u8],
) -> Result<Vec<u8>> {
    let capacity = data
        .len()
        .checked_add(32)
        .ok_or_else(|| Error::Crypto("AES-CBC input too large".into()))?;
    let mut out = vec![0u8; capacity];
    let mut iv = [0u8; 16];
    OsRng.fill_bytes(&mut iv);
    out[..16].copy_from_slice(&iv);
    out[16..16 + data.len()].copy_from_slice(data);
    let enc =
        cbc::Encryptor::<Aes256>::new_from_slices(key, &iv).map_err(|_| Error::Crypto("bad AES key length".into()))?;
    let len = enc
        .encrypt_padded_mut::<P>(&mut out[16..], data.len())
        .map_err(|_| Error::Crypto("AES-CBC input is not block aligned".into()))?
        .len();
    out.truncate(16 + len);
    Ok(out)
}

pub fn decrypt_cbc<P: aes::cipher::block_padding::Padding<aes::cipher::consts::U16>>(
    data: &[u8],
    key: &[u8],
) -> Result<Vec<u8>> {
    if data.len() < 32 {
        return Err(Error::Crypto("AES-CBC ciphertext too short".into()));
    }
    let (iv, body) = data.split_at(16);
    let dec =
        cbc::Decryptor::<Aes256>::new_from_slices(key, iv).map_err(|_| Error::Crypto("bad AES key length".into()))?;
    let mut buf = body.to_vec();
    let len = dec
        .decrypt_padded_mut::<P>(&mut buf)
        .map_err(|_| Error::Crypto("AES-CBC decryption failed".into()))?
        .len();
    buf.truncate(len);
    Ok(buf)
}

pub fn encrypt_aes_v2(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| Error::Crypto("bad AES key length".into()))?;
    let output_len = data
        .len()
        .checked_add(12 + 16)
        .ok_or_else(|| Error::Crypto("AES-GCM input too large".into()))?;
    let mut out = vec![0u8; output_len];
    let (nonce, rest) = out.split_at_mut(12);
    let (body, tag_slot) = rest.split_at_mut(data.len());
    OsRng.fill_bytes(nonce);
    body.copy_from_slice(data);
    let tag = cipher
        .encrypt_in_place_detached(Nonce::from_slice(nonce), b"", body)
        .map_err(|_| Error::Crypto("AES-GCM encryption failed".into()))?;
    tag_slot.copy_from_slice(&tag);
    Ok(out)
}

pub fn decrypt_aes_v2(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 12 + 16 {
        return Err(Error::Crypto("AES-GCM ciphertext too short".into()));
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| Error::Crypto("bad AES key length".into()))?;
    let (nonce, body) = data.split_at(12);
    cipher
        .decrypt(Nonce::from_slice(nonce), body)
        .map_err(|_| Error::Crypto("AES-GCM decryption failed".into()))
}
/// Decrypts a framed CBC ciphertext in place and returns its plaintext window.
pub fn decrypt_cbc_in_place<'a, P: aes::cipher::block_padding::Padding<aes::cipher::consts::U16>>(
    data: &'a mut [u8],
    key: &[u8],
) -> Result<&'a [u8]> {
    if data.len() < 32 {
        return Err(Error::Crypto("AES-CBC ciphertext too short".into()));
    }
    let (iv, body) = data.split_at_mut(16);
    let dec =
        cbc::Decryptor::<Aes256>::new_from_slices(key, iv).map_err(|_| Error::Crypto("bad AES key length".into()))?;
    dec.decrypt_padded_mut::<P>(body)
        .map_err(|_| Error::Crypto("AES-CBC decryption failed".into()))
}

/// Decrypts a framed GCM ciphertext in place and returns its plaintext window.
pub fn decrypt_aes_v2_in_place<'a>(data: &'a mut [u8], key: &[u8]) -> Result<&'a [u8]> {
    if data.len() < 12 + 16 {
        return Err(Error::Crypto("AES-GCM ciphertext too short".into()));
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| Error::Crypto("bad AES key length".into()))?;
    let (nonce, rest) = data.split_at_mut(12);
    let (body, tag) = rest.split_at_mut(rest.len() - 16);
    cipher
        .decrypt_in_place_detached(Nonce::from_slice(nonce), b"", body, Tag::from_slice(tag))
        .map_err(|_| Error::Crypto("AES-GCM decryption failed".into()))?;
    Ok(body)
}

/// Encrypts `[12 spare bytes][plaintext][16 spare bytes]` in place as a framed GCM ciphertext.
pub fn encrypt_aes_v2_in_place(frame: &mut [u8], key: &[u8]) -> Result<()> {
    if frame.len() < 12 + 16 {
        return Err(Error::Crypto("AES-GCM frame too short".into()));
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| Error::Crypto("bad AES key length".into()))?;
    let (nonce, rest) = frame.split_at_mut(12);
    let (body, tag) = rest.split_at_mut(rest.len() - 16);
    OsRng.fill_bytes(nonce);
    let sealed = cipher
        .encrypt_in_place_detached(Nonce::from_slice(nonce), b"", body)
        .map_err(|_| Error::Crypto("AES-GCM encryption failed".into()))?;
    tag.copy_from_slice(&sealed);
    Ok(())
}

fn ecdh_key(secret: &p256::SecretKey, public: &p256::PublicKey) -> [u8; 32] {
    let shared = p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), public.as_affine());
    let digest = Sha256::digest(shared.raw_secret_bytes());
    let mut key = [0u8; 32];
    key.copy_from_slice(&digest);
    key
}

pub fn encrypt_ec(data: &[u8], public: &p256::PublicKey) -> Result<Vec<u8>> {
    let ephemeral = p256::SecretKey::random(&mut OsRng);
    let mut out = ephemeral.public_key().to_encoded_point(false).as_bytes().to_vec();
    out.extend(encrypt_aes_v2(data, &ecdh_key(&ephemeral, public))?);
    Ok(out)
}

pub fn decrypt_ec(data: &[u8], private: &p256::SecretKey) -> Result<Vec<u8>> {
    if data.len() <= EC_PUBLIC_KEY_LEN {
        return Err(Error::Crypto("EC ciphertext too short".into()));
    }
    let (ephemeral, body) = data.split_at(EC_PUBLIC_KEY_LEN);
    let public =
        p256::PublicKey::from_sec1_bytes(ephemeral).map_err(|_| Error::Crypto("invalid EC public key".into()))?;
    decrypt_aes_v2(body, &ecdh_key(private, &public))
}

pub fn load_rsa_private_key(der: &[u8]) -> Result<RsaPrivateKey> {
    RsaPrivateKey::from_pkcs1_der(der)
        .or_else(|_| RsaPrivateKey::from_pkcs8_der(der))
        .map_err(|_| Error::Crypto("invalid RSA private key".into()))
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
        .map_err(|_| Error::Crypto("RSA decryption failed".into()))
}

pub fn derive_keyhash_v1(password: &str, salt: &[u8], iterations: u32) -> Vec<u8> {
    let key = pbkdf2::pbkdf2_hmac_array::<Sha256, 32>(password.as_bytes(), salt, iterations);
    Sha256::digest(key).to_vec()
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
        return Err(Error::Crypto("invalid encryption params length".into()));
    }
    let iterations = u32::from_be_bytes([0, params[1], params[2], params[3]]);
    let key = pbkdf2::pbkdf2_hmac_array::<Sha256, 32>(password.as_bytes(), &params[4..20], iterations);
    let doubled = decrypt_cbc::<NoPadding>(&params[20..], &key)?;
    if doubled.len() != 64 || doubled[..32] != doubled[32..] {
        return Err(Error::Crypto("data key mirror check failed (wrong password?)".into()));
    }
    Ok(doubled[..32].to_vec())
}

#[cfg(test)]
pub fn create_encryption_params(password: &str, salt: &[u8], iterations: u32, data_key: &[u8]) -> Result<Vec<u8>> {
    let key = pbkdf2::pbkdf2_hmac_array::<Sha256, 32>(password.as_bytes(), salt, iterations);
    let mut out = vec![1u8];
    out.extend_from_slice(&iterations.to_be_bytes()[1..]);
    out.extend_from_slice(salt);
    out.extend(encrypt_cbc::<NoPadding>(&[data_key, data_key].concat(), &key)?);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use rsa::RsaPublicKey;

    use super::*;

    #[test]
    fn cbc_and_gcm_roundtrip_and_reject_wrong_key() {
        let key = random_bytes(32);
        let other = random_bytes(32);
        for msg in [&b""[..], b"x", &[7u8; 16], &[9u8; 33]] {
            let cbc = encrypt_cbc::<Pkcs7>(msg, &key).unwrap();
            assert_eq!(cbc.len() % 16, 0);
            assert_eq!(decrypt_cbc::<Pkcs7>(&cbc, &key).unwrap(), msg);
            let mut cbc_in_place = cbc.clone();
            assert_eq!(decrypt_cbc_in_place::<Pkcs7>(&mut cbc_in_place, &key).unwrap(), msg);
            let gcm = encrypt_aes_v2(msg, &key).unwrap();
            assert_eq!(gcm.len(), 12 + msg.len() + 16);
            assert_eq!(decrypt_aes_v2(&gcm, &key).unwrap(), msg);
            assert!(decrypt_aes_v2(&gcm, &other).is_err());
            let mut gcm_in_place = gcm.clone();
            assert_eq!(decrypt_aes_v2_in_place(&mut gcm_in_place, &key).unwrap(), msg);
        }
        let mut gcm_frame = vec![0; 12 + 3 + 16];
        gcm_frame[12..15].copy_from_slice(b"abc");
        encrypt_aes_v2_in_place(&mut gcm_frame, &key).unwrap();
        assert_eq!(decrypt_aes_v2_in_place(&mut gcm_frame, &key).unwrap(), b"abc");
    }

    #[test]
    fn ec_roundtrip_through_serialized_keys() {
        let private = p256::SecretKey::random(&mut OsRng);
        let public_bytes = private.public_key().to_encoded_point(false).as_bytes().to_vec();
        let public = p256::PublicKey::from_sec1_bytes(&public_bytes).unwrap();
        let sealed = encrypt_ec(b"transmission key", &public).unwrap();
        let reloaded = p256::SecretKey::from_slice(&private.to_bytes()).unwrap();
        assert_eq!(decrypt_ec(&sealed, &reloaded).unwrap(), b"transmission key");
        assert!(decrypt_ec(&sealed, &p256::SecretKey::random(&mut OsRng)).is_err());
    }

    #[test]
    fn pbkdf2_sha256_matches_published_vector() {
        // RFC 7914 §11 PBKDF2-HMAC-SHA256 vector (first 32 bytes of the 64-byte output).
        let key = pbkdf2::pbkdf2_hmac_array::<Sha256, 32>(b"passwd", b"salt", 1);
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
            let c = public.encrypt(&mut OsRng, Pkcs1v15Encrypt, b"record key").unwrap();
            if c[0] == 0 {
                break c;
            }
        };
        assert_eq!(decrypt_rsa(&sealed[1..], &private).unwrap(), b"record key");
    }
}
