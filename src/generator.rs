//! Port of Commander's `KeeperPasswordGenerator`: per-category minimums, the remainder drawn
//! from every enabled category, then shuffled.

use std::str::FromStr;

use rand::rngs::OsRng;
use rand::seq::SliceRandom;

use crate::prelude::*;

pub const DEFAULT_LENGTH: usize = 20;
pub const SPECIAL_CHARACTERS: &str = "!@#$%()+;<>=?[]{}^.,";
const DIGITS: &str = "0123456789";
const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ClassCount {
    #[default]
    Any,
    Excluded,
    Minimum(usize),
    Exact(usize),
}

impl From<i32> for ClassCount {
    fn from(count: i32) -> Self {
        match count {
            0 => Self::Excluded,
            n if n > 0 => Self::Minimum(n as usize),
            n => Self::Exact(n.unsigned_abs() as usize),
        }
    }
}

impl ClassCount {
    fn required(self) -> usize {
        match self {
            Self::Any | Self::Excluded => 0,
            Self::Minimum(count) | Self::Exact(count) => count,
        }
    }

    fn allows_extra(self) -> bool {
        matches!(self, Self::Any | Self::Minimum(_))
    }

    fn is_exact(self) -> bool {
        matches!(self, Self::Exact(_))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rules {
    pub length:    usize,
    pub symbols:   ClassCount,
    pub digits:    ClassCount,
    pub uppercase: ClassCount,
    pub lowercase: ClassCount,
}

impl Default for Rules {
    fn default() -> Self {
        Self {
            length:    DEFAULT_LENGTH,
            symbols:   ClassCount::Any,
            digits:    ClassCount::Any,
            uppercase: ClassCount::Any,
            lowercase: ClassCount::Any,
        }
    }
}

impl FromStr for Rules {
    type Err = Error;

    /// Parses `"[length,] upper, lower, digits, symbols"`.
    fn from_str(source: &str) -> Result<Self> {
        let fields = source.split(',').map(str::trim).collect::<Vec<_>>();
        let invalid_rules =
            || Error::Generic("Invalid rules. Format is \"[length,] upper, lower, digits, symbols\"".into());
        let (length, uppercase, lowercase, digits, symbols) = match fields.as_slice() {
            [uppercase, lowercase, digits, symbols] => (DEFAULT_LENGTH, *uppercase, *lowercase, *digits, *symbols),
            [length, uppercase, lowercase, digits, symbols] => {
                (
                    length.parse::<usize>().map_err(|source| {
                        Error::Context {
                            context: "Invalid rule length".into(),
                            source:  Box::new(source.into()),
                        }
                    })?,
                    *uppercase,
                    *lowercase,
                    *digits,
                    *symbols,
                )
            }
            _ => return Err(invalid_rules()),
        };
        let parse_count = |value: &str, field: &str| {
            value.parse::<i32>().map(ClassCount::from).map_err(|source| {
                Error::Context {
                    context: format!("Invalid {field} class count"),
                    source:  Box::new(source.into()),
                }
            })
        };
        Ok(Self {
            length,
            uppercase: parse_count(uppercase, "uppercase")?,
            lowercase: parse_count(lowercase, "lowercase")?,
            digits: parse_count(digits, "digits")?,
            symbols: parse_count(symbols, "symbols")?,
        })
    }
}

pub fn generate(rules: &Rules) -> Result<String> {
    let categories = [
        (rules.symbols, SPECIAL_CHARACTERS),
        (rules.digits, DIGITS),
        (rules.uppercase, UPPER),
        (rules.lowercase, LOWER),
    ];
    let required: usize = categories.iter().map(|(count, _)| count.required()).sum();
    let extra_count = rules.length.saturating_sub(required);
    let mut extra_chars: String = categories
        .iter()
        .filter(|(count, _)| count.allows_extra())
        .map(|(_, chars)| *chars)
        .collect();
    if extra_count > 0 && extra_chars.is_empty() {
        extra_chars = categories
            .iter()
            .filter(|(count, _)| count.is_exact())
            .map(|(_, chars)| *chars)
            .collect();
        if extra_chars.is_empty() {
            return Err(Error::Generic("Password character set is empty".into()));
        }
    }

    let mut rng = OsRng;
    let pick = |chars: &str, count: usize, rng: &mut OsRng| -> Vec<char> {
        (0..count)
            .map(|_| char::from(*chars.as_bytes().choose(rng).expect("non-empty pool")))
            .collect()
    };
    let mut password = Vec::with_capacity(required + extra_count);
    for (count, chars) in categories {
        password.extend(pick(chars, count.required(), &mut rng));
    }
    password.extend(pick(&extra_chars, extra_count, &mut rng));
    password.shuffle(&mut rng);
    Ok(password.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn count(s: &str, set: &str) -> usize {
        s.chars().filter(|c| set.contains(*c)).count()
    }

    #[test]
    fn default_length_and_category_counts() {
        assert_eq!(Rules::default().length, 20);
        for _ in 0..50 {
            let rules = Rules {
                length:    16,
                symbols:   ClassCount::Excluded,
                digits:    ClassCount::Minimum(5),
                uppercase: ClassCount::Minimum(3),
                lowercase: ClassCount::Any,
            };
            let password = generate(&rules).unwrap();
            assert_eq!(password.chars().count(), 16);
            assert_eq!(count(&password, SPECIAL_CHARACTERS), 0);
            assert!(count(&password, DIGITS) >= 5 && count(&password, UPPER) >= 3);
        }
    }

    #[test]
    fn exact_counts_and_minimums_exceeding_length() {
        let rules = Rules {
            length:    4,
            symbols:   ClassCount::Exact(4),
            digits:    ClassCount::Excluded,
            uppercase: ClassCount::Excluded,
            lowercase: ClassCount::Excluded,
        };
        assert_eq!(count(&generate(&rules).unwrap(), SPECIAL_CHARACTERS), 4);
        let rules = Rules {
            length:    2,
            symbols:   ClassCount::Minimum(3),
            digits:    ClassCount::Minimum(3),
            uppercase: ClassCount::Any,
            lowercase: ClassCount::Any,
        };
        assert_eq!(generate(&rules).unwrap().len(), 6);
        let none = Rules {
            length:    8,
            symbols:   ClassCount::Excluded,
            digits:    ClassCount::Excluded,
            uppercase: ClassCount::Excluded,
            lowercase: ClassCount::Excluded,
        };
        assert!(generate(&none).is_err());
    }

    #[test]
    fn parses_rules_with_or_without_length() {
        let rules = "30, 1, 2, 3, 4".parse::<Rules>().unwrap();
        assert_eq!(
            (rules.length, rules.uppercase, rules.lowercase, rules.digits, rules.symbols),
            (30, ClassCount::Minimum(1), ClassCount::Minimum(2), ClassCount::Minimum(3), ClassCount::Minimum(4))
        );
        assert_eq!("1,2,3,4".parse::<Rules>().unwrap().length, DEFAULT_LENGTH);
        assert!("1,2,3".parse::<Rules>().is_err());
        assert!("-1,1,2,3,4".parse::<Rules>().is_err());
    }
}
