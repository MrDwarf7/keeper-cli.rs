//! Port of Commander's `KeeperPasswordGenerator`: per-category minimums, the remainder drawn
//! from every enabled category, then shuffled.

use rand::rngs::OsRng;
use rand::seq::SliceRandom;

use crate::prelude::*;

pub const DEFAULT_LENGTH: usize = 20;
pub const SPECIAL_CHARACTERS: &str = "!@#$%()+;<>=?[]{}^.,";
const DIGITS: &str = "0123456789";
const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";

/// `None` = category allowed with no minimum; `Some(0)` = excluded; `Some(n)` = at least n.
/// Negative counts mean "exactly |n| and nothing more from this category", as in Commander.
#[derive(Clone, Copy, Debug, Default)]
pub struct Rules {
    pub length:    usize,
    pub symbols:   Option<i32>,
    pub digits:    Option<i32>,
    pub uppercase: Option<i32>,
    pub lowercase: Option<i32>,
}

impl Rules {
    /// `"[length,] upper, lower, digits, symbols"`.
    pub fn parse(rules: &str, length: Option<usize>) -> Result<Self> {
        let mut nums = rules
            .split(',')
            .map(|s| s.trim().parse::<i32>())
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| Error::Generic("Invalid rules. Format is \"[length,] upper, lower, digits, symbols\"".into()))?;
        let mut rule_length = None;
        if nums.len() == 5 {
            rule_length = usize::try_from(nums.remove(0)).ok();
        }
        let [uppercase, lowercase, digits, symbols] = nums[..] else {
            return Err(Error::Generic("Invalid rules. Format is \"[length,] upper, lower, digits, symbols\"".into()));
        };
        Ok(Self {
            length:    length.or(rule_length).unwrap_or(DEFAULT_LENGTH),
            symbols:   Some(symbols),
            digits:    Some(digits),
            uppercase: Some(uppercase),
            lowercase: Some(lowercase),
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
    let required: usize = categories.iter().map(|(n, _)| n.unwrap_or(0).unsigned_abs() as usize).sum();
    let extra_count = rules.length.saturating_sub(required);
    let mut extra_chars: String = categories
        .iter()
        .filter(|(n, _)| n.is_none_or(|n| n > 0))
        .map(|(_, chars)| *chars)
        .collect();
    if extra_count > 0 && extra_chars.is_empty() {
        extra_chars = categories.iter().filter(|(n, _)| n.is_some_and(|n| n < 0)).map(|(_, c)| *c).collect();
        if extra_chars.is_empty() {
            return Err(Error::Generic("Password character set is empty".into()));
        }
    }

    let mut rng = OsRng;
    let pick = |chars: &str, count: usize, rng: &mut OsRng| -> Vec<char> {
        let pool: Vec<char> = chars.chars().collect();
        (0..count).map(|_| *pool.choose(rng).expect("non-empty pool")).collect()
    };
    let mut password = Vec::with_capacity(required + extra_count);
    for (n, chars) in categories {
        password.extend(pick(chars, n.unwrap_or(0).unsigned_abs() as usize, &mut rng));
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
    fn minimums_are_met_and_excluded_categories_absent() {
        for _ in 0..50 {
            let rules = Rules { length: 16, symbols: Some(0), digits: Some(5), uppercase: Some(3), lowercase: None };
            let pw = generate(&rules).unwrap();
            assert_eq!(pw.chars().count(), 16);
            assert_eq!(count(&pw, SPECIAL_CHARACTERS), 0);
            assert!(count(&pw, DIGITS) >= 5 && count(&pw, UPPER) >= 3);
        }
    }

    #[test]
    fn negative_counts_are_exact_and_minimums_can_exceed_length() {
        let rules = Rules { length: 4, symbols: Some(-4), digits: Some(0), uppercase: Some(0), lowercase: Some(0) };
        assert_eq!(count(&generate(&rules).unwrap(), SPECIAL_CHARACTERS), 4);
        let rules = Rules { length: 2, symbols: Some(3), digits: Some(3), uppercase: None, lowercase: None };
        assert_eq!(generate(&rules).unwrap().len(), 6);
        let none = Rules { length: 8, symbols: Some(0), digits: Some(0), uppercase: Some(0), lowercase: Some(0) };
        assert!(generate(&none).is_err());
    }

    #[test]
    fn rules_string_with_and_without_length() {
        let r = Rules::parse("30, 1, 2, 3, 4", None).unwrap();
        assert_eq!((r.length, r.uppercase, r.lowercase, r.digits, r.symbols), (30, Some(1), Some(2), Some(3), Some(4)));
        assert_eq!(Rules::parse("1,2,3,4", Some(12)).unwrap().length, 12);
        assert!(Rules::parse("1,2,3", None).is_err());
    }
}
