use crate::utils::coloryze::Coloryze;

use super::common::ask;
use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};
use rfd::FileDialog;
use sha2::digest::{consts::U12, generic_array::GenericArray};

pub fn ask_cipher() -> Aes256Gcm {
    let passphrase = ask("Chosissez une passphrase :").trim().to_string();
    let key: Key<Aes256Gcm> = generate_key_from_passphrase(passphrase);
    let cipher = Aes256Gcm::new(&key);

    return cipher;
}

pub fn encrypt_file() {
    let cipher = ask_cipher();
    let current_dir;

    match std::env::current_dir() {
        Ok(path) => current_dir = path.to_str().unwrap_or("./").to_string(),
        Err(_) => current_dir = "./".to_string(),
    }

    println!("Current directory: {:?}", current_dir);
    println!("Current directory: {:?}", current_dir);

    let file_path = FileDialog::new()
        .set_directory(current_dir)
        .add_filter("All Files", &["*"])
        .pick_file();

    if file_path.is_none() {
        println!(
            "{}",
            Coloryze::red(
                "Aucun fichier séléctionné.\nVeuillez réessayer tout le processus de chiffrement..."
            )
        );
        encrypt_file();
    }

    if let Some(file_path) = file_path {
        let file = std::fs::read(&file_path).expect("Failed to read the file");
        let (nonce, encrypted_file) = encrypt_aes_gcm(&cipher, file.as_ref());

        let file_name = file_path
            .file_name()
            .map(|name| name.to_string_lossy().to_string())
            .unwrap_or_else(|| "output".to_string());
        let output_folder = file_name.clone() + "_crypted";
        std::fs::create_dir(&output_folder).unwrap_or_else(|_| {
            println!(
                "{}",
                Coloryze::red(
                    "Erreur lors de la création du répertoire. peut être est-il déjà existant."
                )
            );
            std::process::exit(1);
        });

        std::fs::write(
            format!("{}/{}.crypted", output_folder, file_name),
            encrypted_file,
        )
        .unwrap();
        std::fs::write(format!("{}/{}.nonce", output_folder, file_name), nonce).unwrap();
        println!(
            "Encryption complete. Files saved as {}.crypted and {}.nonce",
            file_name, file_name
        );
    } else {
        println!("No file selected.");
    }
}

pub fn decrypt_file() {
    let passphrase = ask("Enter the passphrase: ").trim().to_string();
    let key: Key<Aes256Gcm> = generate_key_from_passphrase(passphrase);

    let cipher = Aes256Gcm::new(&key);

    let current_dir;

    match std::env::current_dir() {
        Ok(path) => current_dir = path.to_str().unwrap_or("./").to_string(),
        Err(_) => current_dir = "./".to_string(),
    }

    let encrypted_file_path = FileDialog::new()
        .set_directory(current_dir)
        .add_filter("Encrypted Files", &["crypted"])
        .pick_file();

    if let Some(encrypted_file_path) = encrypted_file_path {
        let encrypted_file =
            std::fs::read(&encrypted_file_path).expect("Failed to read the encrypted file");

        let nonce_file_path = encrypted_file_path.with_extension("nonce");
        let file_nonce = std::fs::read(&nonce_file_path).expect("Failed to read the nonce file");
        let file_nonce = Nonce::from_slice(&file_nonce);

        let decrypted_file = decrypt_aes_gcm(&cipher, &file_nonce, &encrypted_file);

        //replace .ext.crypted with .decrypted.ext
        let decrypted_file_name;
        let decrypted_file_name_lossy = encrypted_file_path
            .to_string_lossy()
            .replace(".crypted", "");
        let mut splitted_decrypted_file_name =
            decrypted_file_name_lossy.split(".").collect::<Vec<&str>>();
        let length = splitted_decrypted_file_name.len();
        if length > 1 {
            splitted_decrypted_file_name.insert(length - 1, "decrypted");
            decrypted_file_name = splitted_decrypted_file_name.join(".");
        } else {
            decrypted_file_name = format!("{}.decrypted", encrypted_file_path.display());
        }

        std::fs::write(&decrypted_file_name, decrypted_file).unwrap();
        println!("Decryption complete. File saved as {}", decrypted_file_name);
    } else {
        println!("No file selected.");
    }
}

pub fn generate_key_from_passphrase(passphrase: String) -> Key<Aes256Gcm> {
    let mut key = [0u8; 32];
    concat_kdf::derive_key_into::<sha2::Sha256>(passphrase.as_bytes(), b"other-info", &mut key)
        .unwrap();

    return Key::<Aes256Gcm>::from_slice(&key).clone();
}

pub fn encrypt_aes_gcm(cipher: &Aes256Gcm, content: &Vec<u8>) -> (GenericArray<u8, U12>, Vec<u8>) {
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 96-bits; unique per message
    let crypted = cipher
        .encrypt(&nonce, content.as_ref())
        .expect("Encryption failure!");
    (nonce, crypted)
}

pub fn decrypt_aes_gcm(
    cipher: &Aes256Gcm,
    nonce: &GenericArray<u8, U12>,
    content: &Vec<u8>,
) -> Vec<u8> {
    let decrypted = cipher
        .decrypt(nonce, content.as_ref())
        .expect("Decryption failure!");
    decrypted
}
