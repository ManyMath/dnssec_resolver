#[path = "../tests/support/mod.rs"]
mod support;

use base64::{Engine, engine::general_purpose::STANDARD};

fn main() {
    let (anchor, messages) = support::fixtures();
    let messages: std::collections::BTreeMap<_, _> = messages
        .into_iter()
        .map(|(name, message)| (name, STANDARD.encode(message.to_vec().unwrap())))
        .collect();
    println!(
        "{}",
        serde_json::json!({"anchor": anchor, "messages": messages})
    );
}
