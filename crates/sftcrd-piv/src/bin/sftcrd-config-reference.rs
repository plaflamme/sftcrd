use sftcrd_piv::CardConfig;
use toml_example::TomlExample;

/// An application that simply prints the reference documentation for the configuration format within an MD codeblock for inclusion in the generated documentation.
///
/// See nix/docs.nix
fn main() {
    println!("```toml");
    println!("{}", CardConfig::toml_example());
    println!("```");
}
