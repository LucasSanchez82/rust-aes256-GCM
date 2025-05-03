use sha2::digest::consts::U4;

use crate::utils::coloryze::Coloryze;

pub fn ask(question: &str) -> String {
    println!("{}", question);
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).unwrap();
    return input;
}

pub fn ask_password(question: &str) -> String {
    println!("{}", question);
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).unwrap();
    return input;
}

pub fn ask_number_small(question: &str) -> u8 {
    println!("{}", question);
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).unwrap();
    return match input.trim().parse::<u8>() {
        Ok(num) => num,
        Err(_) => {
            println!("{}", Coloryze::red("Invalid input. Please enter a number."));
            return ask_number_small(question);
        }
    };
}
