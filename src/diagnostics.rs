use std::io::IsTerminal;

use tracing_subscriber::filter::{LevelFilter, filter_fn};
use tracing_subscriber::prelude::*;
use tracing_subscriber::{EnvFilter, fmt};

use crate::error::{ApiFailure, Error};

pub fn init(verbosity: Verbosity) -> crate::Result<()> {
    let default_level = match verbosity {
        Verbosity::Normal => LevelFilter::INFO,
        Verbosity::Debug => LevelFilter::DEBUG,
    };
    let env_filter = EnvFilter::builder()
        .with_default_directive(default_level.into())
        .with_env_var("RUST_LOG")
        .from_env()?;
    let ansi = std::io::stderr().is_terminal();

    tracing_subscriber::registry()
        .with(env_filter)
        .with(
            fmt::layer()
                .with_writer(std::io::stderr)
                .with_ansi(ansi)
                .with_filter(filter_fn(|metadata| is_project_target(metadata.target()))),
        )
        .try_init()?;
    Ok(())
}

fn is_project_target(target: &str) -> bool {
    target == env!("CARGO_CRATE_NAME") || target.starts_with(concat!(env!("CARGO_CRATE_NAME"), "::"))
}

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
        Error::DownloadBatch { failures }
        | Error::AttachmentBatch { failures }
        | Error::RecordEditFindings { failures } => {
            write_indent(f, depth)?;
            writeln!(f, "{error}")?;
            for (index, failure) in failures.iter().enumerate() {
                write_indent(f, depth + 1)?;
                writeln!(f, "failure {}:", index + 1)?;
                write_error(f, failure, depth + 2, verbosity)?;
            }
            Ok(())
        }
        Error::Json(error) => {
            write_indent(f, depth)?;
            writeln!(f, "JSON error: {}", safe_json_error(error))
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
        } else if let Some(json) = cause.downcast_ref::<serde_json::Error>() {
            write!(f, "{}", safe_json_error(json))?;
        } else {
            write!(f, "{cause}")?;
        }
        writeln!(f)?;
        source = cause.source();
    }
    Ok(())
}

pub(crate) fn error_kind(error: &Error) -> &'static str {
    match error {
        Error::Context { .. } => "context",
        Error::DownloadBatch { .. } => "download batch",
        Error::AttachmentBatch { .. } => "attachment transfer batch",
        Error::WorkerPanic(_) => "attachment transfer worker panic",
        Error::TransferBudgetPoisoned { .. } => "attachment transfer synchronization error",
        Error::RecordEditFindings { .. } => "record edit findings",
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
        Error::HeaderValue(_) => "HTTP header error",
        Error::Json(_) => "JSON error",
        Error::Http(_) => "HTTP error",
        Error::Decode(_) => "decode error",
        Error::UnknownEnum(_) => "protocol enum error",
        Error::Config(_) => "configuration error",
        Error::TracingFilter(_) => "tracing filter error",
        Error::Tracing(_) => "diagnostics initialization error",
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

fn safe_json_error(error: &serde_json::Error) -> String {
    let category = match error.classify() {
        serde_json::error::Category::Io => "I/O",
        serde_json::error::Category::Syntax => "syntax",
        serde_json::error::Category::Data => "data",
        serde_json::error::Category::Eof => "unexpected end",
    };
    format!("JSON {category} error at line {} column {}", error.line(), error.column())
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
    fn project_target_boundary_excludes_dependencies_and_lookalikes() {
        assert!(is_project_target(env!("CARGO_CRATE_NAME")));
        assert!(is_project_target(concat!(env!("CARGO_CRATE_NAME"), "::diagnostics")));
        assert!(!is_project_target("reqwest"));
        assert!(!is_project_target("hyper"));
        assert!(!is_project_target(concat!(env!("CARGO_CRATE_NAME"), "_evil")));
    }

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

    #[test]
    fn json_payload_error_keeps_source_but_redacts_payload_from_reports() {
        let source =
            serde_json::from_str::<crate::vault::RecordField>(r#"{"type":"text","privacyScreen":"sentinel-secret"}"#)
                .expect_err("privacyScreen has the wrong JSON type");
        assert!(source.to_string().contains("sentinel-secret"));
        let error = Error::Context {
            context: "decoding record UID R1".into(),
            source:  Box::new(Error::Json(source)),
        };
        for verbosity in [Verbosity::Normal, Verbosity::Debug] {
            let output = Report {
                error: &error,
                verbosity,
            }
            .to_string();
            assert!(output.contains("decoding record UID R1"));
            assert!(output.contains("JSON data error"));
            assert!(!output.contains("sentinel-secret"));
        }
    }
    #[test]
    fn worker_panic_payload_is_inspectable_but_not_reported() {
        let marker = "private-panic-payload";
        let payload: Box<dyn std::any::Any + Send> = Box::new(marker.to_owned());
        let worker_panic = crate::error::WorkerPanic::from(payload);
        assert_eq!(worker_panic.as_ref().downcast_ref::<String>().map(String::as_str), Some(marker));
        let error = Error::WorkerPanic(worker_panic);
        for verbosity in [Verbosity::Normal, Verbosity::Debug] {
            let output = Report {
                error: &error,
                verbosity,
            }
            .to_string();
            assert!(output.contains("worker panicked"));
            assert!(!output.contains(marker));
        }
    }
}
