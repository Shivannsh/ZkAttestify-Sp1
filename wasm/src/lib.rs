use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
// use web_sys::console
use sp1_sdk::{ProverClient, SP1ProofWithPublicValues};

#[derive(Serialize, Deserialize)]
struct ReceiptVerificationResult {
    verified: bool,
    error: String,
}

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const ADDRESS_ELF: &[u8] = include_bytes!("../../elf/riscv32im-succinct-zkvm-elf");

#[wasm_bindgen]
pub fn verify_proof_json(proof_json: &str) -> Result<JsValue, JsValue> {
    let client = ProverClient::new();
    let (_, vk) = client.setup(ADDRESS_ELF);
    let proof = SP1ProofWithPublicValues::load(proof_json).unwrap();

    let mut result = ReceiptVerificationResult {
        verified: false,
        error: "".to_string(),
    };

    match client.verify(&proof, &vk) {
        Ok(()) => {
            result.verified = true;
        }
        Err(e) => {
            result.error = e.to_string();
        }
    };
    match serde_wasm_bindgen::to_value(&result) {
        Ok(value) => Ok(value),
        Err(e) => Err(JsValue::from_str(&e.to_string())),
    }
}
