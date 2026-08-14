use std::{env, error::Error, fmt, process::ExitCode};

use crate::{config, server};

const APP_NAME: &str = "BareProxy";
const DEFAULT_CONFIG_PATH: &str = "bareproxy.conf";
const STARTUP_ERROR_EXIT_CODE: u8 = 1;
const CLI_ERROR_EXIT_CODE: u8 = 2;

#[derive(Debug, PartialEq, Eq)]
enum Command {
    Run { config_path: String },
    Help,
    Version,
}

#[derive(Debug, PartialEq, Eq)]
enum AppError {
    UnknownArgument(String),
    MissingConfigPath,
    TooManyArguments,
    Config {
        message: String,
    },
    ListenerBind {
        address: &'static str,
        message: String,
    },
    Server {
        message: String,
    },
}

impl fmt::Display for AppError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownArgument(argument) => write!(formatter, "unknown argument: {argument}"),
            Self::MissingConfigPath => write!(formatter, "--config requires a path"),
            Self::TooManyArguments => write!(formatter, "too many arguments"),
            Self::Config { message } => write!(formatter, "configuration error: {message}"),
            Self::ListenerBind { address, message } => {
                write!(formatter, "failed to listen on {address}: {message}")
            }
            Self::Server { message } => write!(formatter, "server error: {message}"),
        }
    }
}

impl Error for AppError {}

impl AppError {
    fn exit_code(&self) -> u8 {
        match self {
            Self::Config { .. } | Self::ListenerBind { .. } | Self::Server { .. } => {
                STARTUP_ERROR_EXIT_CODE
            }
            Self::UnknownArgument(_) | Self::MissingConfigPath | Self::TooManyArguments => {
                CLI_ERROR_EXIT_CODE
            }
        }
    }
}

pub fn main_exit_code() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{APP_NAME}: {error}");
            ExitCode::from(error.exit_code())
        }
    }
}

fn run() -> Result<(), AppError> {
    match parse_args(env::args().skip(1))? {
        Command::Run { config_path } => start_proxy(&config_path)?,
        Command::Help => print_help(),
        Command::Version => println!("{APP_NAME} {}", env!("CARGO_PKG_VERSION")),
    }

    Ok(())
}

fn start_proxy(config_path: &str) -> Result<(), AppError> {
    print_startup_banner(config_path);

    let config = config::load(config_path).map_err(|source| AppError::Config {
        message: source.to_string(),
    })?;

    println!("Loaded {} route(s)", config.routes().len());
    println!("Max connections: {}", config.max_connections());
    println!(
        "Client idle timeout: {}s",
        config.client_idle_timeout_seconds()
    );

    for route in config.routes() {
        println!("Route: {route}");
    }

    let listener = server::bind_listener().map_err(|source| AppError::ListenerBind {
        address: server::DEV_LISTEN_ADDR,
        message: source.to_string(),
    })?;

    println!("Listening on http://{}", server::DEV_LISTEN_ADDR);

    server::serve(&listener, &config).map_err(|source| AppError::Server {
        message: source.to_string(),
    })
}

fn parse_args<I>(args: I) -> Result<Command, AppError>
where
    I: IntoIterator<Item = String>,
{
    let mut args = args.into_iter();

    let command = match args.next().as_deref() {
        None => Command::Run {
            config_path: DEFAULT_CONFIG_PATH.to_owned(),
        },
        Some("--help" | "-h") => Command::Help,
        Some("--version" | "-V") => Command::Version,
        Some("--config" | "-c") => {
            let config_path = args.next().ok_or(AppError::MissingConfigPath)?;
            Command::Run { config_path }
        }
        Some(argument) => return Err(AppError::UnknownArgument(argument.to_owned())),
    };

    if args.next().is_some() {
        return Err(AppError::TooManyArguments);
    }

    Ok(command)
}

fn print_startup_banner(config_path: &str) {
    println!("{APP_NAME} {}", env!("CARGO_PKG_VERSION"));
    println!("Dependency-free Rust reverse proxy");
    println!("Config: {config_path}");
}

fn print_help() {
    println!("{APP_NAME} {}", env!("CARGO_PKG_VERSION"));
    println!();
    println!("USAGE:");
    println!("    bareproxy [OPTIONS]");
    println!();
    println!("OPTIONS:");
    println!("    -c, --config <PATH>    Use a custom configuration file");
    println!("    -h, --help             Print help");
    println!("    -V, --version          Print version");
    println!();
    println!("Default config: {DEFAULT_CONFIG_PATH}");
}

#[cfg(test)]
mod tests {
    use super::{AppError, Command, parse_args};

    #[test]
    fn no_arguments_runs_proxy_with_default_config() {
        assert_eq!(
            parse_args(Vec::new()),
            Ok(Command::Run {
                config_path: "bareproxy.conf".to_owned(),
            })
        );
    }

    #[test]
    fn config_flag_selects_custom_path() {
        assert_eq!(
            parse_args(vec!["--config".to_owned(), "custom.conf".to_owned()]),
            Ok(Command::Run {
                config_path: "custom.conf".to_owned(),
            })
        );
    }

    #[test]
    fn short_config_flag_selects_custom_path() {
        assert_eq!(
            parse_args(vec!["-c".to_owned(), "custom.conf".to_owned()]),
            Ok(Command::Run {
                config_path: "custom.conf".to_owned(),
            })
        );
    }

    #[test]
    fn missing_config_path_is_rejected() {
        assert_eq!(
            parse_args(vec!["--config".to_owned()]),
            Err(AppError::MissingConfigPath)
        );
    }

    #[test]
    fn help_flag_selects_help() {
        assert_eq!(parse_args(vec!["--help".to_owned()]), Ok(Command::Help));
    }

    #[test]
    fn version_flag_selects_version() {
        assert_eq!(
            parse_args(vec!["--version".to_owned()]),
            Ok(Command::Version)
        );
    }

    #[test]
    fn unknown_argument_is_rejected() {
        assert_eq!(
            parse_args(vec!["--wat".to_owned()]),
            Err(AppError::UnknownArgument("--wat".to_owned()))
        );
    }

    #[test]
    fn extra_argument_is_rejected() {
        assert_eq!(
            parse_args(vec!["--help".to_owned(), "extra".to_owned()]),
            Err(AppError::TooManyArguments)
        );
    }

    #[test]
    fn duplicate_config_argument_is_rejected() {
        assert_eq!(
            parse_args(vec![
                "--config".to_owned(),
                "one.conf".to_owned(),
                "--config".to_owned(),
                "two.conf".to_owned(),
            ]),
            Err(AppError::TooManyArguments)
        );
    }

    #[test]
    fn cli_error_uses_exit_code_two() {
        assert_eq!(AppError::MissingConfigPath.exit_code(), 2);
    }

    #[test]
    fn listener_error_uses_exit_code_one() {
        assert_eq!(
            AppError::ListenerBind {
                address: "127.0.0.1:8080",
                message: "address already in use".to_owned(),
            }
            .exit_code(),
            1
        );
    }

    #[test]
    fn server_error_uses_exit_code_one() {
        assert_eq!(
            AppError::Server {
                message: "accept failed".to_owned(),
            }
            .exit_code(),
            1
        );
    }

    #[test]
    fn config_error_uses_exit_code_one() {
        assert_eq!(
            AppError::Config {
                message: "bad config".to_owned(),
            }
            .exit_code(),
            1
        );
    }
}
