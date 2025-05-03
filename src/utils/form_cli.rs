use crate::utils::{coloryze::Coloryze, common::ask_number_small};

pub struct FormCli {
    options: Vec<(String, fn())>,
}

impl FormCli {
    pub fn add_option(&mut self, name: String, action: fn()) -> &mut FormCli {
        self.options.push((name, action));
        return self;
    }

    pub fn run(&self) {
        println!("{}", Coloryze::blue("Choisissez une option :"));

        for (index, (option, _)) in self.options.iter().enumerate() {
            println!(
                "{}. {}",
                Coloryze::blue(format!("{}", index + 1).as_str()),
                option
            );
        }
        let choice = ask_number_small("Qu'est-ce que vous avez choisit ? ");
        if choice > 0 && usize::from(choice) <= self.options.len() {
            let (_, action) = &self.options[choice as usize - 1];
            action();
        } else {
            println!("{}", Coloryze::red("Choix invalide. Veuillez réessayer."));
            self.run();
        }
    }

    pub fn new() -> Self {
        FormCli {
            options: Vec::new(),
        }
    }
}
