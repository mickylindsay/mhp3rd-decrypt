use clap::{Parser, Subcommand};

mod crypt;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// decrypt and unpack mhp3rd binary into directory
    Unpack {
        #[arg(long, default_value = "DATA.BIN")]
        input: String,

        #[arg(long, default_value = "out")]
        output_dir: String,
    },

    /// encrypt and repack directory into mhp3rd binary
    Repack {
        #[arg(long, default_value = "")]
        input_dir: String,

        #[arg(long, default_value = "REPACK.BIN")]
        output: String,
    },
}
fn main() {
    let cli = Cli::parse();
    match &cli.command {
        Command::Unpack { input, output_dir } => {
            crypt::unpack_all(input, output_dir);
        }
        Command::Repack { input_dir, output } => {
            crypt::repack_all(output, input_dir);
        }
    }
}
