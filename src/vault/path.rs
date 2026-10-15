use std::convert::Infallible;
use std::str::FromStr;

use super::Location;

/// Whether a virtual path starts at the vault root or the current folder.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathAnchor {
    Root,
    Current,
}

/// A parsed Commander path. `//` encodes a literal slash inside a component.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultPath {
    pub anchor:             PathAnchor,
    pub components:         Vec<String>,
    /// Keeps an unescaped final slash distinct from an escaped slash in the last component.
    pub trailing_separator: bool,
}

impl From<&str> for VaultPath {
    fn from(path: &str) -> Self {
        let bytes = path.as_bytes();
        let leading_slashes = bytes.iter().take_while(|&&byte| byte == b'/').count();
        let anchor = if leading_slashes % 2 == 1 {
            PathAnchor::Root
        } else {
            PathAnchor::Current
        };
        let mut index = usize::from(anchor == PathAnchor::Root);
        let mut components = Vec::new();
        let mut component = String::new();
        let mut trailing_separator = false;

        while index < bytes.len() {
            if bytes[index] != b'/' {
                let start = index;
                while index < bytes.len() && bytes[index] != b'/' {
                    index += 1;
                }
                component.push_str(&path[start..index]);
                trailing_separator = false;
            } else if bytes.get(index + 1) == Some(&b'/') {
                component.push('/');
                index += 2;
                trailing_separator = false;
            } else {
                if !component.is_empty() {
                    components.push(std::mem::take(&mut component));
                }
                trailing_separator = true;
                index += 1;
            }
        }
        if !component.is_empty() {
            components.push(component);
        }

        Self {
            anchor,
            components,
            trailing_separator,
        }
    }
}

impl FromStr for VaultPath {
    type Err = Infallible;

    fn from_str(path: &str) -> Result<Self, Self::Err> {
        Ok(path.into())
    }
}

impl std::fmt::Display for VaultPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.anchor == PathAnchor::Root {
            f.write_str("/")?;
        }
        for (index, component) in self.components.iter().enumerate() {
            if index > 0 {
                f.write_str("/")?;
            }
            let mut start = 0;
            for (slash, character) in component.char_indices() {
                if character == '/' {
                    f.write_str(&component[start..slash])?;
                    f.write_str("//")?;
                    start = slash + character.len_utf8();
                }
            }
            f.write_str(&component[start..])?;
        }
        if self.trailing_separator && !self.components.is_empty() {
            f.write_str("/")?;
        }
        Ok(())
    }
}

/// Exact folder resolution or the deepest existing folder plus an unresolved suffix.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PathResolution {
    /// Every path component exists.
    Full(Location),
    /// `parent` is the deepest existing folder; `tail` contains the remaining path.
    Partial { parent: Location, tail: VaultPath },
}

impl TryFrom<PathResolution> for Location {
    type Error = VaultPath;

    fn try_from(resolution: PathResolution) -> Result<Self, Self::Error> {
        match resolution {
            PathResolution::Full(location) => Ok(location),
            PathResolution::Partial { tail, .. } => Err(tail),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{PathAnchor, VaultPath};

    #[test]
    fn virtual_paths_round_trip_with_commander_escaping() {
        for source in [
            "",
            ".",
            "..",
            "/",
            "//",
            "///leading",
            "////",
            "/Work/a//b",
            "A///B",
            "/Work/Infra/missing/a//b/",
            r"folder\name",
        ] {
            let path = source.parse::<VaultPath>().unwrap();
            let rendered = path.to_string();
            assert_eq!(rendered, source, "{source:?}");
            assert_eq!(rendered.parse::<VaultPath>().unwrap(), path, "{source:?}");
        }
    }

    #[test]
    fn leading_slash_parity_selects_the_anchor() {
        assert_eq!("/one".parse::<VaultPath>().unwrap().anchor, PathAnchor::Root);
        assert_eq!("//one".parse::<VaultPath>().unwrap().anchor, PathAnchor::Current);
        assert_eq!("///one".parse::<VaultPath>().unwrap().anchor, PathAnchor::Root);
        assert_eq!("////one".parse::<VaultPath>().unwrap().anchor, PathAnchor::Current);
    }
}
