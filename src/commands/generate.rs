use clap::Args;

use super::{App, Run, Table};
use crate::cli::Format;
use crate::generator::{self, Rules};

#[derive(Args, Debug)]
pub struct Generate {
    #[arg(short = 'c', long = "count")]
    length:    Option<usize>,
    #[arg(short, long, default_value_t = 1)]
    number:    usize,
    #[arg(short, long)]
    rules:     Option<String>,
    #[arg(short, long, allow_negative_numbers = true)]
    symbols:   Option<i32>,
    #[arg(short, long, allow_negative_numbers = true)]
    digits:    Option<i32>,
    #[arg(short, long, allow_negative_numbers = true)]
    uppercase: Option<i32>,
    #[arg(short, long, allow_negative_numbers = true)]
    lowercase: Option<i32>,
    #[arg(long, value_enum, default_value_t = Format::Table)]
    format:    Format,
}

impl Run for Generate {
    fn run(self, _: &mut App) -> crate::Result<()> {
        let has_counts = [self.symbols, self.digits, self.uppercase, self.lowercase]
            .iter()
            .any(Option::is_some);
        let mut rules = if has_counts {
            if self.rules.is_some() {
                eprintln!("Ignoring --rules because explicit character-count options were supplied.");
            }
            Rules {
                symbols: self.symbols.map(generator::ClassCount::from).unwrap_or_default(),
                digits: self.digits.map(generator::ClassCount::from).unwrap_or_default(),
                uppercase: self.uppercase.map(generator::ClassCount::from).unwrap_or_default(),
                lowercase: self.lowercase.map(generator::ClassCount::from).unwrap_or_default(),
                ..Rules::default()
            }
        } else {
            self.rules
                .map(|source| source.parse::<Rules>())
                .transpose()?
                .unwrap_or_default()
        };
        if let Some(length) = self.length {
            rules.length = length;
        }
        let passwords = (0..self.number)
            .map(|_| generator::generate(&rules))
            .collect::<crate::Result<Vec<_>>>()?;
        match self.format {
            Format::Json => println!("{}", serde_json::to_string_pretty(&passwords)?),
            Format::Table => {
                let mut table = Table::new(&["password"]);
                table.extend(passwords.into_iter().map(|password| vec![password]));
                table.print(Format::Table);
            }
        }
        Ok(())
    }
}
