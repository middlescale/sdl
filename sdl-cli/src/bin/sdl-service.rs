fn main() {
    std::process::exit(sdl_cli::app::run_service_from_args(
        std::env::args().collect(),
    ));
}
