mod utils;

use utils::common::ask;
use utils::crypt_snippets::{decrypt_file, encrypt_file};
fn main() -> () {
    println!("Choose an option:");
    println!("1. Encrypt a file");
    println!("2. Decrypt a file");
    let choice = ask("Enter your choice (1 or 2): ").trim().to_string();

    match choice.as_str() {
        "1" => encrypt_file(),
        "2" => decrypt_file(),
        _ => println!("Invalid choice. Please restart the program and choose 1 or 2."),
    }
}
