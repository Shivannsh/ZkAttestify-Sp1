mod helper;
mod structs;

use alloy_sol_types::SolType;
use clap::Parser;
use ethers_core::types::{Signature, H160, H256};
use fibonacci_lib::PublicValuesStruct;
use helper::domain_separator;
use sp1_sdk::{HashableKey, ProverClient, SP1ProofWithPublicValues, SP1Stdin};
use std::fs;
use structs::{Attest, InputData};

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const ADDRESS_ELF: &[u8] = include_bytes!("../../../elf/riscv32im-succinct-zkvm-elf");

/// The arguments for the command.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(long)]
    execute: bool,

    #[clap(long)]
    prove: bool,
}

fn main() {
    // Setup the logger.
    sp1_sdk::utils::setup_logger();

    // Parse the command line arguments.
    let args = Args::parse();

    if args.execute == args.prove {
        eprintln!("Error: You must specify either --execute or --prove");
        std::process::exit(1);
    }
    // ------------------------------------------------------------------------------------------------------------------------------------------------

    let json_str = fs::read_to_string("./input.json").unwrap();
    let input_data: InputData = serde_json::from_str(&json_str).unwrap();

    let domain = ethers_core::types::transaction::eip712::EIP712Domain {
        name: Some(input_data.sig.domain.name),
        version: Some(input_data.sig.domain.version),
        chain_id: Some(
            ethers_core::types::U256::from_dec_str(&input_data.sig.domain.chain_id).unwrap(),
        ),
        verifying_contract: Some(input_data.sig.domain.verifying_contract.parse().unwrap()),
        salt: None,
    };

    let signer_address: H160 = input_data.signer.parse().unwrap();

    let message = Attest {
        version: input_data.sig.message.version,
        schema: input_data.sig.message.schema.parse().unwrap(),
        recipient: input_data.sig.message.recipient.parse().unwrap(),
        time: input_data.sig.message.time.parse().unwrap(),
        expiration_time: input_data.sig.message.expiration_time.parse().unwrap(),
        revocable: input_data.sig.message.revocable,
        ref_uid: input_data.sig.message.ref_uid.parse().unwrap(),
        data: ethers_core::utils::hex::decode(&input_data.sig.message.data[2..]).unwrap(),
        salt: input_data.sig.message.salt.parse().unwrap(),
    };

    // Calculate the current timestamp and the threshold age
    let current_timestamp = chrono::Utc::now().timestamp() as u64;
    let threshold_age: u64 = 18 * 365 * 24 * 60 * 60; // 18 years in seconds

    // Calculate the domain separator and the message hash
    let domain_separator = domain_separator(
        &domain,
        ethers_core::utils::keccak256(
            b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
        )
        .into(),
    );

    // Parse the signature
    let signature = ethers_core::types::Signature {
        r: input_data.sig.signature.r.parse().unwrap(),
        s: input_data.sig.signature.s.parse().unwrap(),
        v: input_data.sig.signature.v.into(),
    };

    // ------------------------------------------------------------------------------------------------------------------------------------------------

    // Setup the prover client.
    let client = ProverClient::new();

    // Setup the inputs.
    let mut stdin = SP1Stdin::new();
    stdin.write(&signer_address);
    stdin.write(&signature);
    stdin.write(&threshold_age);
    stdin.write(&current_timestamp);
    stdin.write(&message);
    stdin.write(&domain_separator);

    if args.execute {
        // Execute the program
        let (output, report) = client.execute(ADDRESS_ELF, stdin).run().unwrap();
        println!("Program executed successfully.");

        // Read the output.
        let decoded = PublicValuesStruct::abi_decode(output.as_slice(), true).unwrap();
        let PublicValuesStruct {
            signer_address,
            current_timestamp,
            threshold_age,
            attest_time,
            receipent_address,
            domain_seperator,
        } = decoded;
        println!("Signer Address: {:?}", signer_address);
        println!("Current Timestamp: {:?}", current_timestamp);
        println!("Threshold Age: {:?}", threshold_age);
        println!("Attest Time: {:?}", attest_time);
        println!("Receipent Address: {:?}", receipent_address);
        println!("Domain Seperator: {:?}", domain_seperator);

        // Record the number of cycles executed.
        println!("Number of cycles: {}", report.total_instruction_count());
    } else {
        // Setup the program for proving.
        let (pk, vk) = client.setup(ADDRESS_ELF);
        // Generate the proof
        let proof = client
            .prove(&pk, stdin)
            .run()
            .expect("failed to generate proof");

        // Test a round trip of proof serialization and deserialization.
        proof
            .save("proof.bin")
            .expect("saving proof failed");
        println!("Successfully generated proof!");

        // Verify the proof.
       
        client.verify(&proof, &vk).expect("verification failed");
        println!("Successfully verified proof!");

        // Printing the vkey
        let vk_bytes32 = vk.bytes32();
        println!("vk_bytes32: {:?}", vk_bytes32);

        // Printing the public values
        let deserialized_proof =
            SP1ProofWithPublicValues::load("/home/whoisgautxm/Desktop/ZkAttestify-Sp1/script/proof.bin").expect("loading proof failed");
        let public_inputs = deserialized_proof.public_values;
        let decoded = PublicValuesStruct::abi_decode(public_inputs.as_slice(), true).unwrap();
        let PublicValuesStruct {
            signer_address,
            current_timestamp,
            threshold_age,
            attest_time,
            receipent_address,
            domain_seperator,
        } = decoded;
        println!("Signer Address: {:?}", signer_address);
        println!("Current Timestamp: {:?}", current_timestamp);
        println!("Threshold Age: {:?}", threshold_age);
        println!("Attest Time: {:?}", attest_time);
        println!("Receipent Address: {:?}", receipent_address);
        println!("Domain Seperator: {:?}", domain_seperator);

     
    }
}
