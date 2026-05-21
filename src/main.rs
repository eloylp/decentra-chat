use decentra_chat::{config::Config, storage::Storage};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::load()?;
    let _storage = Storage::open(&config.storage_path)?;

    println!(
        "DecentraChat storage initialized at {}",
        config.storage_path.display()
    );

    Ok(())
}
