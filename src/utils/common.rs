pub fn ask(question: &str) -> String {
    println!("{}", question);
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).unwrap();
    return input;
}
