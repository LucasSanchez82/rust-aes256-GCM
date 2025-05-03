mod utils;

use utils::{
    crypt_snippets::{decrypt_file, encrypt_file},
    form_cli::FormCli,
};

fn main() -> () {
    FormCli::new()
        .add_option("Chiffrer un fichier", encrypt_file)
        .add_option("Déchiffrer un fichier", decrypt_file)
        .run();
}
