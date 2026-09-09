use std::{fmt, str::FromStr};

use chrono::NaiveDate;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

const DOCS_URL: &str = "https://docs.evervault.com/primitives/functions#function.toml";

/// The languages a Function can be written in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Language {
    Node,
    Python,
}

impl Language {
    pub const ALL: [Language; 2] = [Language::Node, Language::Python];

    const fn as_str(&self) -> &'static str {
        match self {
            Language::Node => "node",
            Language::Python => "python",
        }
    }

    fn runtime(
        self,
        version: &str,
        runtime: &str,
    ) -> Result<FunctionRuntime, InvalidFunctionRuntime> {
        match (self, split_version(version)) {
            (Language::Node, Some((major, None))) => Ok(FunctionRuntime::Node { major }),
            (Language::Node, _) => Err(InvalidFunctionRuntime::NodeVersion(runtime.to_string())),

            (Language::Python, Some((major, Some(minor)))) => {
                Ok(FunctionRuntime::Python { major, minor })
            }
            (Language::Python, _) => {
                Err(InvalidFunctionRuntime::PythonVersion(runtime.to_string()))
            }
        }
    }
}

impl fmt::Display for Language {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Language {
    type Err = InvalidFunctionRuntime;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Language::ALL
            .into_iter()
            .find(|lang| lang.as_str() == s)
            .ok_or_else(|| InvalidFunctionRuntime::Malformed(s.to_string()))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FunctionRuntime {
    Node { major: u32 },
    Python { major: u32, minor: u32 },
}

/// Where a runtime is in its life, as far as the CLI knows.
///
/// A runtime is deprecated first - it still deploys, but it's on its way out -
/// and becomes obsolete once the platform stops accepting deployments using it.
/// Both carry the date they took effect and the reason for it, so the CLI can
/// tell a user why their Function needs moving.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lifecycle {
    /// Deploys cleanly - no end of life has been announced.
    Active,
    /// Still deploys, with a warning.
    Deprecated { on: NaiveDate, reason: &'static str },
    /// The platform no longer accepts deployments using it.
    Obsolete { on: NaiveDate, reason: &'static str },
}

struct SupportedRuntime {
    runtime: FunctionRuntime,
    lifecycle: Lifecycle,
}

impl SupportedRuntime {
    const fn new(runtime: FunctionRuntime, lifecycle: Lifecycle) -> Self {
        Self { runtime, lifecycle }
    }
}

/// Ordered as it's presented to the user when selecting a runtime.
const SUPPORTED_RUNTIMES: &[SupportedRuntime] = &[
    SupportedRuntime::new(FunctionRuntime::Node { major: 18 }, Lifecycle::Active),
    SupportedRuntime::new(FunctionRuntime::Node { major: 20 }, Lifecycle::Active),
    SupportedRuntime::new(
        FunctionRuntime::Python { major: 3, minor: 9 },
        Lifecycle::Active,
    ),
    SupportedRuntime::new(
        FunctionRuntime::Python {
            major: 3,
            minor: 10,
        },
        Lifecycle::Active,
    ),
    SupportedRuntime::new(
        FunctionRuntime::Python {
            major: 3,
            minor: 11,
        },
        Lifecycle::Active,
    ),
];

impl FunctionRuntime {
    /// Every runtime the CLI knows the platform supports.
    pub fn supported() -> impl Iterator<Item = FunctionRuntime> {
        SUPPORTED_RUNTIMES.iter().map(|supported| supported.runtime)
    }

    /// Where this runtime is in its life. A runtime the CLI doesn't know about
    /// is treated as active - the API has the final say on what it accepts.
    pub fn lifecycle(&self) -> Lifecycle {
        SUPPORTED_RUNTIMES
            .iter()
            .find(|supported| supported.runtime == *self)
            .map_or(Lifecycle::Active, |supported| supported.lifecycle)
    }
}

impl fmt::Display for FunctionRuntime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FunctionRuntime::Node { major } => write!(f, "{}@{}", Language::Node, major),
            FunctionRuntime::Python { major, minor } => {
                write!(f, "{}@{}.{}", Language::Python, major, minor)
            }
        }
    }
}

#[derive(Debug, Error)]
pub enum InvalidFunctionRuntime {
    #[error("Invalid function language \"{0}\". Must be one of: (node|python)@version. eg node@18, python@3.11. See {DOCS_URL} for supported language versions.")]
    Malformed(String),
    #[error("Invalid function language \"{0}\". Node versions are given as a major version only. eg node@18. See {DOCS_URL} for supported language versions.")]
    NodeVersion(String),
    #[error("Invalid function language \"{0}\". Python versions are given as a major and minor version. eg python@3.11. See {DOCS_URL} for supported language versions.")]
    PythonVersion(String),
}

/// Splits `18` into `(18, None)` and `3.11` into `(3, Some(11))`. Anything else
/// - empty components, non-digits, a third component - isn't a version.
fn split_version(version: &str) -> Option<(u32, Option<u32>)> {
    fn component(component: &str) -> Option<u32> {
        // `u32::from_str` accepts a leading `+`, which we don't want here.
        if component.is_empty() || !component.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        component.parse().ok()
    }

    match version.split_once('.') {
        Some((major, minor)) => Some((component(major)?, Some(component(minor)?))),
        None => Some((component(version)?, None)),
    }
}

impl FromStr for FunctionRuntime {
    type Err = InvalidFunctionRuntime;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Surrounding whitespace in a hand-written function.toml is harmless.
        let runtime = s.trim();
        let (language, version) = runtime
            .split_once('@')
            .ok_or_else(|| InvalidFunctionRuntime::Malformed(runtime.to_string()))?;

        language.parse::<Language>()?.runtime(version, runtime)
    }
}

impl Serialize for FunctionRuntime {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for FunctionRuntime {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let runtime = String::deserialize(deserializer)?;
        runtime.parse().map_err(de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_renders_supported_runtimes() {
        for runtime in FunctionRuntime::supported() {
            let rendered = runtime.to_string();
            assert_eq!(rendered.parse::<FunctionRuntime>().unwrap(), runtime);
        }
    }

    #[test]
    fn renders_each_language_with_the_versions_it_is_pinned_to() {
        assert_eq!(FunctionRuntime::Node { major: 20 }.to_string(), "node@20");
        assert_eq!(
            FunctionRuntime::Python {
                major: 3,
                minor: 11
            }
            .to_string(),
            "python@3.11"
        );
    }

    #[test]
    fn parses_runtimes_the_cli_doesnt_know_about() {
        // A function.toml can name a runtime released after this version of the
        // CLI, so an unrecognised runtime isn't an invalid one - the API has the
        // final say on what it will accept.
        let runtime: FunctionRuntime = "node@99".parse().unwrap();
        assert_eq!(runtime, FunctionRuntime::Node { major: 99 });
        assert_eq!(runtime.lifecycle(), Lifecycle::Active);
        assert!(!FunctionRuntime::supported().any(|supported| supported == runtime));
    }

    #[test]
    fn requires_a_minor_version_for_python_and_rejects_one_for_node() {
        assert!(matches!(
            "python@3".parse::<FunctionRuntime>(),
            Err(InvalidFunctionRuntime::PythonVersion(_))
        ));
        assert!(matches!(
            "node@18.20".parse::<FunctionRuntime>(),
            Err(InvalidFunctionRuntime::NodeVersion(_))
        ));
    }

    #[test]
    fn tolerates_surrounding_whitespace() {
        assert_eq!(
            " node@18\n".parse::<FunctionRuntime>().unwrap(),
            FunctionRuntime::Node { major: 18 }
        );
    }

    #[test]
    fn rejects_malformed_runtimes() {
        for input in [
            "",
            "node",
            "node@",
            "@18",
            "ruby@3.4",
            "node@v18",
            "python@3.",
            "python@3.13.1",
            "python@+3.13",
            "node@18 python@3.13",
            "run node@18 please",
        ] {
            assert!(
                input.parse::<FunctionRuntime>().is_err(),
                "expected \"{input}\" to be rejected"
            );
        }
    }
}
