use std::{env, error::Error, fmt, process::ExitCode};

const APP_NAME: &str = "BareProxy";
const DEFAULT_CONFIG_PATH: &str = "bareproxy.conf";
const CLI_ERROR_EXIT_CODE: u8 = 2;

#[derive(Debug, PartialEq, Eq)]
enum Command {
    Run,
    Help,
    Version,
}

#[derive(Debug, PartialEq, Eq)]
enum AppError {
    UnknownArgument(String),
    TooManyArguments,
}

impl fmt::Display for AppError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownArgument(argument) => write!(formatter, "unknown argument: {argument}"),
            Self::TooManyArguments => write!(formatter, "too many arguments"),
        }
    }
}

impl Error for AppError {}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{APP_NAME}: {error}");
            ExitCode::from(CLI_ERROR_EXIT_CODE)
        }
    }
}

fn run() -> Result<(), AppError> {
    match parse_args(env::args().skip(1))? {
        Command::Run => print_startup_banner(),
        Command::Help => print_help(),
        Command::Version => println!("{APP_NAME} {}", env!("CARGO_PKG_VERSION")),
    }

    Ok(())
}

fn parse_args<I>(args: I) -> Result<Command, AppError>
where
    I: IntoIterator<Item = String>,
{
    let mut args = args.into_iter();

    let command = match args.next().as_deref() {
        None => Command::Run,
        Some("--help" | "-h") => Command::Help,
        Some("--version" | "-V") => Command::Version,
        Some(argument) => return Err(AppError::UnknownArgument(argument.to_owned())),
    };

    if args.next().is_some() {
        return Err(AppError::TooManyArguments);
    }

    Ok(command)
}

fn print_startup_banner() {
    println!("{APP_NAME} {}", env!("CARGO_PKG_VERSION"));
    println!("Dependency-free Rust reverse proxy");
    println!("Default config: {DEFAULT_CONFIG_PATH}");
}

fn print_help() {
    println!("{APP_NAME} {}", env!("CARGO_PKG_VERSION"));
    println!();
    println!("USAGE:");
    println!("    bareproxy [OPTION]");
    println!();
    println!("OPTIONS:");
    println!("    -h, --help       Print help");
    println!("    -V, --version    Print version");
    println!();
    println!("Default config: {DEFAULT_CONFIG_PATH}");
}

#[cfg(test)]
mod tests {
    use super::{AppError, Command, parse_args};

    #[test]
    fn no_arguments_runs_proxy() {
        assert_eq!(parse_args(Vec::new()), Ok(Command::Run));
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
}
