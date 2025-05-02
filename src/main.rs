mod utils;
use std::fmt::format;

use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};
use base64::Engine;
use rfd::FileDialog;
use sha2::digest::{consts::U12, generic_array::GenericArray};
use utils::common::ask;

fn main() -> () {
    let passphrase = ask("enter a passphrase : ").trim().to_string();
    // let text_to_encrypt = ask("Enter the text to encrypt:").trim().to_string();
    // println!("\nyou would encrypt: {}", text_to_encrypt);

    let key: Key<Aes256Gcm> = generate_key_from_passphrase(passphrase);

    let cipher = Aes256Gcm::new(&key);

    let file_path = FileDialog::new()
        .add_filter("All Files", &["*"])
        .pick_file();

    let file = file_path
        .as_ref()
        .and_then(|path| std::fs::read_to_string(path).ok());

    let (nonce, encrypted_file) = encrypt_aes_cgm(&cipher, file.as_ref().unwrap());
    println!("file: {:?}", file);
    println!("encrypted file: {:?}", &encrypted_file);
    let file_name = file_path
        .as_ref()
        .and_then(|path| {
            path.file_name()
                .map(|name| name.to_string_lossy().to_string())
        })
        .unwrap_or_else(|| "output".to_string());
    std::fs::write(format!("{}.crypted", file_name), encrypted_file).unwrap();
    std::fs::write(format!("{}.nonce", file_name), nonce).unwrap();

    let encrypted_file = std::fs::read(format!("{}.crypted", file_name)).unwrap(); // Correct file path
    let file_nonce = std::fs::read(format!("{}.nonce", file_name)).unwrap(); // Correct nonce file
    println!("encrypted file: {:?}", encrypted_file);
    println!("file nonce: {:?}", file_nonce);
    let file_nonce = Nonce::from_slice(&file_nonce);
    let decrypted_file = decrypt_aes_cgm(&cipher, &file_nonce, &encrypted_file);
    println!("decrypted file: {:?}", decrypted_file);
    std::fs::write(format!("{}.decrypted.sql", file_name), decrypted_file).unwrap();
}
fn generate_key_from_passphrase(passphrase: String) -> Key<Aes256Gcm> {
    let mut key = [0u8; 32];
    concat_kdf::derive_key_into::<sha2::Sha256>(passphrase.as_bytes(), b"other-info", &mut key)
        .unwrap();

    return Key::<Aes256Gcm>::from_slice(&key).clone();
}

fn encrypt_aes_cgm(cipher: &Aes256Gcm, text: &str) -> (GenericArray<u8, U12>, Vec<u8>) {
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 96-bits; unique per message
    let ciphertext = cipher
        .encrypt(&nonce, text.as_ref())
        .expect("encryption failure!");
    (nonce, ciphertext)
}
fn encrypt_aes_cgm_base64(cipher: &Aes256Gcm, text: &str) -> (GenericArray<u8, U12>, String) {
    let (nonce, ciphertext) = encrypt_aes_cgm(cipher, text);
    (
        nonce,
        base64::engine::general_purpose::STANDARD.encode(ciphertext),
    )
}
fn decrypt_aes_cgm(cipher: &Aes256Gcm, nonce: &GenericArray<u8, U12>, text: &Vec<u8>) -> String {
    let plaintext = cipher
        .decrypt(nonce, text.as_ref())
        .expect("decryption failure!");
    String::from_utf8_lossy(&plaintext).to_string()
}

fn decrypt_aes_cgm_base64(
    cipher: &Aes256Gcm,
    nonce_base64: &GenericArray<u8, U12>,
    text: &str,
) -> String {
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(text)
        .expect("invalid ciphertext");
    return decrypt_aes_cgm(cipher, nonce_base64, &decoded);
}
