mod app;
mod config;
mod http;
mod proxy;
mod server;

fn main() -> std::process::ExitCode {
    app::main_exit_code()
}
