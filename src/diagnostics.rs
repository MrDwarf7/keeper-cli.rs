use crate::error::{ApiFailure, Error};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verbosity {
    Normal,
    Debug,
}

impl From<bool> for Verbosity {
    fn from(debug: bool) -> Self {
        if debug { Self::Debug } else { Self::Normal }
    }
}

pub struct Report<'a> {
    pub error:     &'a Error,
    pub verbosity: Verbosity,
}

impl std::fmt::Display for Report<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write_error(f, self.error, 0, self.verbosity)
    }
}

fn write_error(f: &mut std::fmt::Formatter<'_>, error: &Error, depth: usize, verbosity: Verbosity) -> std::fmt::Result {
    match error {
        Error::Context { context, source } => {
            write_indent(f, depth)?;
            writeln!(f, "{context}")?;
            write_error(f, source, depth + 1, verbosity)
        }
        Error::DownloadBatch { failures } => {
            write_indent(f, depth)?;
            writeln!(f, "{error}")?;
            for (index, failure) in failures.iter().enumerate() {
                write_indent(f, depth + 1)?;
                writeln!(f, "failure {}:", index + 1)?;
                write_error(f, failure, depth + 2, verbosity)?;
            }
            Ok(())
        }
        Error::Api(failure) => write_api_failure(f, failure, depth, verbosity),
        Error::Http(error) => {
            write_indent(f, depth)?;
            writeln!(f, "HTTP request failed: {}", safe_http_error(error))?;
            if verbosity == Verbosity::Debug {
                write_sources(f, error, depth)?;
            }
            Ok(())
        }
        _ => {
            write_indent(f, depth)?;
            if verbosity == Verbosity::Debug {
                writeln!(f, "{}: {error}", error_kind(error))?;
                write_sources(f, error, depth)
            } else {
                writeln!(f, "{error}")
            }
        }
    }
}

fn write_indent(f: &mut std::fmt::Formatter<'_>, depth: usize) -> std::fmt::Result {
    write!(f, "{:width$}", "", width = depth * 2)
}

fn write_sources(f: &mut std::fmt::Formatter<'_>, error: &dyn std::error::Error, depth: usize) -> std::fmt::Result {
    let mut source = error.source();
    while let Some(cause) = source {
        write_indent(f, depth + 1)?;
        write!(f, "caused by: ")?;
        if let Some(http) = cause.downcast_ref::<reqwest::Error>() {
            write!(f, "{}", safe_http_error(http))?;
        } else {
            write!(f, "{cause}")?;
        }
        writeln!(f)?;
        source = cause.source();
    }
    Ok(())
}

fn error_kind(error: &Error) -> &'static str {
    match error {
        Error::Context { .. } => "context",
        Error::DownloadBatch { .. } => "download batch",
        Error::Generic(_) => "generic error",
        Error::Api(_) => "API error",
        Error::Crypto(_) => "cryptographic error",
        Error::P256(_) => "P-256 error",
        Error::NotLoggedIn => "authentication error",
        Error::Cancelled => "cancellation",
        Error::Io(_) => "I/O error",
        Error::Utf8(_) => "UTF-8 error",
        Error::Integer(_) => "integer conversion error",
        Error::ParseInt(_) => "integer parsing error",
        Error::Base64(_) => "base64 decoding error",
        Error::Allocation(_) => "allocation error",
        Error::Json(_) => "JSON error",
        Error::Http(_) => "HTTP error",
        Error::Decode(_) => "decode error",
        Error::UnknownEnum(_) => "protocol enum error",
        Error::Config(_) => "configuration error",
    }
}

fn write_api_failure(
    f: &mut std::fmt::Formatter<'_>,
    failure: &ApiFailure,
    depth: usize,
    verbosity: Verbosity,
) -> std::fmt::Result {
    write_indent(f, depth)?;
    if verbosity == Verbosity::Debug {
        writeln!(f, "API error: {}: {}", failure.error, failure.message)
    } else {
        writeln!(f, "{}: {}", failure.error, failure.message)
    }
}

fn safe_http_error(error: &reqwest::Error) -> String {
    match error.url() {
        Some(url) => {
            let message = error.to_string();
            if message.contains(url.as_str()) {
                sanitize_url_in_message(&message, url)
            } else {
                format!("request failed ({})", safe_url(url))
            }
        }
        None => error.to_string(),
    }
}

fn sanitize_url_in_message(message: &str, url: &reqwest::Url) -> String {
    message.replace(url.as_str(), &safe_url(url))
}

fn safe_url(url: &reqwest::Url) -> String {
    let origin = url.origin().ascii_serialization();
    if origin == "null" {
        "<redacted URL>".into()
    } else {
        format!("{origin}{}", url.path())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nested_batch_and_http_secrets_are_visible_or_redacted() {
        let error = Error::Context {
            context: "downloading attachments".into(),
            source:  Box::new(Error::DownloadBatch {
                failures: vec![
                    Error::Context {
                        context: "report.pdf".into(),
                        source:  Box::new(Error::Generic("permission denied".into())),
                    },
                    Error::Generic("photo.jpg: disk full".into()),
                ],
            }),
        };
        let normal = Report {
            error:     &error,
            verbosity: Verbosity::Normal,
        }
        .to_string();
        let debug = Report {
            error:     &error,
            verbosity: Verbosity::Debug,
        }
        .to_string();
        assert!(normal.contains("report.pdf"));
        assert!(normal.contains("permission denied"));
        assert!(normal.contains("photo.jpg: disk full"));
        assert!(debug.contains("report.pdf"));
        assert!(debug.contains("permission denied"));
        assert!(debug.contains("photo.jpg: disk full"));
        assert!(debug.contains("generic error"));
        assert_ne!(normal, debug);

        let api = Error::Api(ApiFailure {
            error: "access_denied".into(),
            message: "request rejected".into(),
            additional_info: Some("api-secret".into()),
            ..Default::default()
        });
        let api_output = Report {
            error:     &api,
            verbosity: Verbosity::Debug,
        }
        .to_string();
        assert!(!api_output.contains("api-secret"));

        let client = reqwest::blocking::Client::builder().https_only(true).build().unwrap();
        let http_error = client
            .get("http://user:password@example.test/private?token=query-secret#fragment-secret")
            .send()
            .unwrap_err();
        let http_error = Error::Http(http_error);
        let normal_http = Report {
            error:     &http_error,
            verbosity: Verbosity::Normal,
        }
        .to_string();
        let debug_http = Report {
            error:     &http_error,
            verbosity: Verbosity::Debug,
        }
        .to_string();
        for output in [&normal_http, &debug_http] {
            assert!(output.contains("example.test/private"));
            assert!(!output.contains("user"));
            assert!(!output.contains("password"));
            assert!(!output.contains("query-secret"));
            assert!(!output.contains("fragment-secret"));
        }
    }
}
