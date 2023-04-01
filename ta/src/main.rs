#![no_main]                                                     // Directs the compiler that the main function is not the standard entry point
use std::{vec, num::NonZeroU32, str, io::Write, ops::Sub};      // Import the standard library
use bigint::{U256, U512};                                       // Import the bigint library, used to handle big integers in calculations
use hex;                                                        // Import the hex library, used to convert bytes to hex strings and vice versa

// Import the optee_utee library, used to interact with the OP-TEE OS
use optee_utee::{ta_close_session, ta_create, ta_destroy, ta_invoke_command, ta_open_session, trace_println};
use optee_utee::{PersistentObject, ObjectStorageConstants, DataFlag, TransientObject, TransientObjectType, AttributeMemref, AttributeId};
use optee_utee::{Error, ErrorKind, Parameters, Result, ParamType};
use optee_utee::{Random, Mac, AlgorithmId, Digest};

// Import the bitcoin_transaction module
use proto::{Command, bitcoin_transaction};
use bitcoin_transaction::Transaction;

// Import some libraries used to deal with the bitcoin protocol
use ring::pbkdf2;                                                              
use secp256k1::{constants::CURVE_ORDER, Secp256k1, SecretKey, PublicKey, Message};
use ripemd::{Ripemd160, Digest as RipemdDigest};

// Global variables
static MASTER_KEY_ID: u8 = 57;          // Master key ID
static DEFAULT_PIN: u32 = 1234;         // Default PIN code
static CKD_LEVEL_0: u32 = 0;            // Constant used to derive the first child key level (m/0')
static CKD_LEVEL_1: u32 = 1;            // Constant used to derive the second child key level (m/0'/0)

/**
 * @brief Trusted Application Creation Function
 * @return Ok()
*/
#[ta_create]
fn create() -> Result<()> {
    trace_println!("[+] Bitcoin Wallet TA create");
    Ok(())
}

/**
 * @brief Trusted Application Open Session Function
 * @arg _params: Parameters passed by the client
 * @return Ok()
*/
#[ta_open_session]
fn open_session(_params: &mut Parameters) -> Result<()> {
    trace_println!("[+] Bitcoin Wallet TA open session");
    Ok(())
}

/**
 * @brief Trusted Application Close Session Function
*/
#[ta_close_session]
fn close_session() {
    trace_println!("[+] Bitcoin Wallet TA close session");
}

/**
 * @brief Trusted Application Destroy Function
 * @return Ok()
*/
#[ta_destroy]
fn destroy() {
    trace_println!("[+] Bitcoin Wallet TA destroy");
}

/**
 * @brief Trusted Application Invoke Command Function
 * @arg cmd_id specifies the command to be executed
 * @arg params specifies the parameters passed by the Client Application
 * @return Ok() if the command is executed successfully, otherwise returns an error code
*/
#[ta_invoke_command]
fn invoke_command(cmd_id: u32, params: &mut Parameters) -> Result<()> {
    trace_println!("[+] Bitcoin Wallet TA invoke command");

    // Match the command ID with the command to be executed
    match Command::from(cmd_id) {
        Command::CheckMasterKey => {                            // Check if the master key exists
            return check_master_key(params);    
        }
        Command::GenerateMasterKey => {                         // Generate a new master key
            return generate_master_key(params);
        }
        Command::MnemonicToMasterKey => {                       // Derive the master key from the mnemonic
            return mnemonic_to_master_key(params);
        }
        Command::EraseMasterKey => {                            // Erase the master key
            return erase_master_key(params);
        }
        Command::SignTransaction => {                           // Sign a transaction
            return sign_transaction(params);
        }
        Command::GetBitcoinAddress => {                         // Get the bitcoin address
            return get_bitcoin_address(params);
        }
        _ => Err(Error::new(ErrorKind::BadParameters)),    // Return an error if the command ID is not valid
    }
}


/*********************** PUBLIC FUNCTIONS ***********************/

/**
 * @brief Check if the master key exists
 * @arg params specifies the parameters passed by the Client Application
 * @return Ok() if the master key exists, otherwise returns an error code
*/
pub fn check_master_key(params: &mut Parameters) -> Result<()> {
    // Check if the parameters are correct 
    let param_types = (ParamType::ValueInput as u32, ParamType::None as u32, ParamType::None as u32, ParamType::None as u32);
    if (params.0.param_type as u32, params.1.param_type as u32, params.2.param_type as u32, params.3.param_type as u32) != param_types {
        return Err(Error::new(ErrorKind::BadParameters));
    }

    // Get the PIN code
    let pin = unsafe {params.0.as_value().unwrap()};

    // Check if the PIN is correct
    if pin.a() != DEFAULT_PIN {
        return Err(Error::new(ErrorKind::AccessDenied));
    }

    // Check if the master key exists
    check_if_master_key_exist()
}

/**
 * @brief Generate a new master key
 * @arg params specifies the parameters passed by the Client Application
 * @return Ok() if the master key is generated successfully, otherwise returns an error code
*/
pub fn generate_master_key(params: &mut Parameters) -> Result<()> {
    // Check if the parameters are correct
    let param_types = (ParamType::ValueInput as u32, ParamType::MemrefOutput as u32, ParamType::None as u32, ParamType::None as u32);
    if (params.0.param_type as u32, params.1.param_type as u32, params.2.param_type as u32, params.3.param_type as u32) != param_types {
        return Err(Error::new(ErrorKind::BadParameters));
    }

    // Get the PIN code
    let pin = unsafe {params.0.as_value().unwrap()};

    // Check if the PIN is correct
    if pin.a() != DEFAULT_PIN {
        return Err(Error::new(ErrorKind::AccessDenied));
    }

    // Generate a new random mnemonic
    match generate_random_mnemonic(256) {
        Err(_e) => return Err(Error::new(ErrorKind::BadState)),
        Ok(mnemonic) => {
            // Set the mnemonic in the output buffer
            let mut mnemonic_buffer = unsafe {params.1.as_memref().unwrap()};
            match mnemonic_buffer.buffer().write(mnemonic.as_bytes()) {
                Ok(_n) => trace_println!("Mnemonic: {:?}", mnemonic),
                Err(_e) => return Err(Error::new(ErrorKind::BadState)),
            }

            // Generate the seed based on the mnemonic
            let seed: [u8; 64] = from_mnemonic_to_seed(&mnemonic, &"".to_string());

            // Generate the extended master key (master key + master chain code) based on the seed
            match master_seed_to_master_key(&seed)
            {
                Err(_e) => return Err(Error::new(ErrorKind::BadState)),
                Ok(ext_master_key) => {
                    // Define the object identifier
                    let mut master_key_id = vec![MASTER_KEY_ID; 8];
                    match PersistentObject::create(ObjectStorageConstants::Private, 
                                                    &mut master_key_id, 
                                                    DataFlag::ACCESS_READ | DataFlag::ACCESS_WRITE | DataFlag::ACCESS_WRITE_META | DataFlag::SHARE_READ | DataFlag::SHARE_WRITE,
                                                    None,
                                                    &ext_master_key) {
                        Ok(mut obj) => {
                            // Write the master key in the object
                            match obj.write(&ext_master_key) {
                                Ok(_n) => {
                                    trace_println!("Extended Master Key base10 {:?}", U256::from_big_endian(&ext_master_key[0..32]));
                                    trace_println!("Extended Master Key base16 {:?}", hex::encode(&ext_master_key[0..32]));
                                    return Ok(());
                                }
                                Err(e) => {
                                    return Err(e);
                                }
                            }
                        }
                        Err(e) => {
                            return Err(e);
                        }
                    }
                }
            }
        }
    }
}

/**
 * @brief Derive the master key from the mnemonic
 * @arg params specifies the parameters passed by the Client Application
 * @return Ok() if the master key is derived successfully, otherwise returns an error code
*/
pub fn mnemonic_to_master_key(params: &mut Parameters) -> Result<()> {
    // Check if the parameters are correct
    let param_types = (ParamType::ValueInput as u32, ParamType::MemrefInput as u32, ParamType::None as u32, ParamType::None as u32);

    if (params.0.param_type as u32, params.1.param_type as u32, params.2.param_type as u32, params.3.param_type as u32) != param_types {
        return Err(Error::new(ErrorKind::BadParameters));
    }

    // Get the PIN code
    let pin = unsafe {params.0.as_value().unwrap()};

    // Check if the PIN is correct
    if pin.a() != DEFAULT_PIN {
        return Err(Error::new(ErrorKind::AccessDenied));
    }

    // Get the mnemonic
    let mut mnemonic_buffer = unsafe {params.1.as_memref().unwrap()};
    let mnemonic = mnemonic_buffer.buffer();

    // Generate the seed based on the mnemonic
    let seed: [u8; 64] = from_mnemonic_to_seed(&(str::from_utf8(&mnemonic).unwrap().to_string()), &"".to_string());

    // Generate the extended master key (master key + master chain code) based on the seed
    match master_seed_to_master_key(&seed)
    {
        Err(_e) => return Err(Error::new(ErrorKind::BadState)),
        Ok(ext_master_key) => {
            // Define the object identifier
            let mut master_key_id = vec![MASTER_KEY_ID; 8];
            match PersistentObject::create(ObjectStorageConstants::Private, 
                                            &mut master_key_id, 
                                            DataFlag::ACCESS_READ | DataFlag::ACCESS_WRITE | DataFlag::ACCESS_WRITE_META | DataFlag::SHARE_READ | DataFlag::SHARE_WRITE,
                                            None,
                                            &ext_master_key) {
                Ok(mut obj) => {
                    // Write the master key in the object
                    match obj.write(&ext_master_key) {
                        Ok(_n) => {
                            trace_println!("Extended Master Key {:?}", ext_master_key);
                            return Ok(());
                        }
                        Err(e) => {
                            return Err(e);
                        }
                    }
                }
                Err(e) => {
                    return Err(e);
                }
            }
        }
    }
}

/**
 * @brief Erase the master key
 * @arg params specifies the parameters passed by the Client Application
 * @return Ok() if the master key is erased successfully, otherwise returns an error code
*/
pub fn erase_master_key(params: &mut Parameters) -> Result<()> {
    // Define the object identifier
    let mut master_key_id = vec![MASTER_KEY_ID; 8];

    // Check if the parameters are correct 
    let param_types = (ParamType::ValueInput as u32, ParamType::None as u32, ParamType::None as u32, ParamType::None as u32);
    if (params.0.param_type as u32, params.1.param_type as u32, params.2.param_type as u32, params.3.param_type as u32) != param_types {
        return Err(Error::new(ErrorKind::BadParameters));
    }

    // Get the PIN code
    let pin = unsafe {params.0.as_value().unwrap()};

    // Check if the PIN is correct
    if pin.a() != DEFAULT_PIN {
        return Err(Error::new(ErrorKind::AccessDenied));
    }

    // Open the master key object, if it exists
    match PersistentObject::open(ObjectStorageConstants::Private, &mut master_key_id, DataFlag::ACCESS_READ | DataFlag::ACCESS_WRITE_META) {
        // If the master key exists, close the object and return Ok
        Ok(mut obj) => {
            PersistentObject::close_and_delete(&mut obj)?;
            return Ok(());
        }
        // If the master key does not exist, return an error
        Err(e) => {
            return Err(e);
        }
    }
}

/**
 * @brief Request the Bitcoin address associated to an account
 * @arg params specifies the parameters passed by the Client Application
 * @return Ok() if the bitcoin address was successfully created, otherwise returns an error code
*/
pub fn get_bitcoin_address(params: &mut Parameters) -> Result<()> {
    // Check if the parameters are correct 
    let param_types = (ParamType::ValueInput as u32, ParamType::MemrefOutput as u32, ParamType::None as u32, ParamType::None as u32);
    if (params.0.param_type as u32, params.1.param_type as u32, params.2.param_type as u32, params.3.param_type as u32) != param_types {
        return Err(Error::new(ErrorKind::BadParameters));
    }

    // Get the PIN code and account ID
    let value = unsafe {params.0.as_value().unwrap()};

    // Check if the PIN is correct
    if value.a() != DEFAULT_PIN {
        return Err(Error::new(ErrorKind::AccessDenied));
    }

    // Get the account ID
    let account_id = value.b();

    // Extract which level of derivation is required
    let level: u32 = account_id / 10;

    // Extract the index of the derivation
    let mut index: u32 = account_id % 10;

    // If the level is 0, the index must be shifted by 31 bits for HD wallet Hardended derivation
    if level == CKD_LEVEL_0 {
        index = index + (1 << 31);
    }

    // Generate the private child key
    match generate_private_child_key(level, index) 
    {
        Err(e) => return Err(e),
        Ok(private_child_key) => 
        {
            // Generate the public key
            match generate_public_key_compressed(private_child_key) 
            {
                Err(e) => return Err(e),
                Ok(public_key) =>
                {
                    // Generate the Bitcoin address from the compressed public key
                    match generate_bitcoin_address(public_key) 
                    {
                        Err(e) => return Err(e),
                        Ok(bitcoin_address) =>
                        {
                            // Encode the Bitcoin address in base58
                            match base_58_check_encode(bitcoin_address, true) 
                            {
                                Err(e) => return Err(e),
                                Ok(bitcoin_address_base58) =>
                                {
                                    // Set the output buffer
                                    let mut output_buffer = unsafe {params.1.as_memref().unwrap()};
                                    match output_buffer.buffer().write(&bitcoin_address_base58) {
                                        Ok(_n) => return Ok(()),
                                        Err(_e) => return Err(Error::new(ErrorKind::BadState)),
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

/**
 * @brief Sign a transaction
 * @arg params specifies the parameters passed by the Client Application
 * @return Ok() if the transaction was successfully signed, otherwise returns an error code
*/
pub fn sign_transaction(params: &mut Parameters) -> Result<()> {
    // Check if the parameters are correct 
    let param_types = (ParamType::ValueInput as u32, ParamType::MemrefInput as u32, ParamType::MemrefOutput as u32, ParamType::None as u32);
    if (params.0.param_type as u32, params.1.param_type as u32, params.2.param_type as u32, params.3.param_type as u32) != param_types {
        return Err(Error::new(ErrorKind::BadParameters));
    }

    // Get the PIN code
    let value = unsafe {params.0.as_value().unwrap()};

    // Check if the PIN is correct
    if value.a() != DEFAULT_PIN {
        return Err(Error::new(ErrorKind::AccessDenied));
    }

    // Get the account ID
    let account_id = value.b();

    // Extract which level of derivation is required
    let level: u32 = account_id / 10;

    // Extract the index of the derivation
    let mut index: u32 = account_id % 10;

    // If the level is 0, the index must be shifted by 31 bits for HD wallet Hardended derivation
    if level == CKD_LEVEL_0 {
        index = index + (1 << 31);
    }

    // Get the transaction data
    let mut transaction_data = unsafe {params.1.as_memref().unwrap()};
    let mut transaction_data = transaction_data.buffer();
    trace_println!("Transaction data: {:?}", transaction_data);
    let mut transaction: Transaction = Transaction::deserialize(transaction_data);
    trace_println!("Transaction data: {:?}", transaction);

    // Append the SIGHASH_ALL flag to the transaction data
    let tx_data = [transaction_data.to_vec(), [1u8].to_vec()].concat();

    // Generate the private key
    let private_key: [u8; 32] = match generate_private_child_key(level, index)
    {
        Ok(private_key) => private_key,
        Err(_e) => {
            trace_println!("Error generating the private key");
            return Err(Error::new(ErrorKind::BadState));
        }
    };

    // Generate the public key
    let public_key: [u8; 33] = match generate_public_key_compressed(private_key)
    {
        Ok(public_key) => public_key,
        Err(_e) => {
            trace_println!("Error generating the public key");
            return Err(Error::new(ErrorKind::BadState));
        }
    };

    // Sign the transaction
    let der_signature = match sign(private_key, public_key, &tx_data)
    {
        Err(e) => return Err(e),
        Ok(der_signature) => der_signature,
    };

    // Print the signature
    trace_println!("Signature: {}", hex::encode(&der_signature));

    // Create the script signature
    let script_sig = [bitcoin_transaction::var_int(der_signature.len()+1), der_signature.to_vec(), [1u8].to_vec(), [33u8].to_vec(), public_key.to_vec()].concat();

    // Set the script signature
    transaction.inputs[0].script_sig = script_sig;

    // Serialize the transaction
    let serialized_transaction = transaction.serialize();

    // Set the output buffer
    let mut out_buffer = unsafe {params.2.as_memref().unwrap()};
    out_buffer.buffer().write(&serialized_transaction);

    // Return Ok
    Ok(())
}

/*********************** PRIVATE FUNCTIONS ***********************/

/**
 * @brief Generate a random mnemonic
 * @arg strength The strength of the mnemonic
 * @return Mnemonic
*/
fn generate_random_mnemonic(strength: u32) -> Result<String>{
    // Define the entropy
    let mut entropy = [0u8; 32];

    // Define the mnemonic number of words
    let mnemonic_number = strength / 8 * 3 / 4; 

    // Define the entropy hash
    let mut entropy_hash = [0u8; 32];

    // Generate a random entropy
    Random::generate(&mut entropy);

    // Define the mnemonic
    let mut mnemonic = String::new();

    // Allocate a SHA256 Digest operation
    match Digest::allocate(AlgorithmId::Sha256) 
    {
        Err(_e) => return Err(Error::new(ErrorKind::BadState)),
        Ok(digest) => {
            match digest.do_final(&entropy, &mut entropy_hash) {
                Err(_e) => return Err(Error::new(ErrorKind::BadState)),
                Ok(_n) => {
                    // Calculate the checksum
                    let checksum = entropy_hash[0];

                    // Define the entropy + checksum
                    let mut entropy_checksum = [0u8; 33];
                    entropy_checksum[0..32].copy_from_slice(&entropy);
                    entropy_checksum[32] = checksum;
                    
                    // Convert the entropy + checksum into a mnemonic
                    for i in 0..mnemonic_number {
                        // Get the index of the word
                        let mut idx = 0;
                        // Divide the sequence of bits into groups of 11 bits (2048 words)
                        for j in 0..11 {
                            idx <<= 1;
                            // Map each group of 11 bits to a word
                            let aux: usize = ((i * 11 + j) / 8) as usize;
                            if (entropy_checksum[aux] & (1 << (7 - ((i * 11 + j) % 8)))) > 0 {
                                idx += 1;
                            }
                        }
                        mnemonic.push_str(BIP39_EN_WORDS[idx]);
                        mnemonic.push_str(" ");
                    }
                    // Remove the last space
                    mnemonic.pop();
                }
            }
        }
    }
    Ok(mnemonic)
}

/**
 * @brief Generate a seed from a mnemonic
 * @arg mnemonic The mnemonic
 * @return Seed
*/
fn from_mnemonic_to_seed(mnemonic: &String, passphrase: &String) -> [u8; 64] {
    // Define the salt
    let mut salt = String::new();
    salt.push_str("mnemonic");
    salt.push_str(passphrase);

    // Define the seed
    let mut seed = [0u8; 64];

    // Convert the mnemonic to a byte array
    let mnemonic_bytes = mnemonic.as_bytes();
    let salt_bytes = salt.as_bytes();

    // Create the Algoritm (PBKDF2_HMAC_SHA512)
    static PBKDF2_ALG: pbkdf2::Algorithm = pbkdf2::PBKDF2_HMAC_SHA512;

    // Derive the seed
    pbkdf2::derive(PBKDF2_ALG, NonZeroU32::new(2048).unwrap(), &salt_bytes, &mnemonic_bytes, &mut seed);

    // Print the seed
    trace_println!("Seed: {:?}", seed);
    trace_println!("Seed base16 {:?}", hex::encode(&seed));

    seed
}

/**
 * @brief Generate the Master key from a seed
 * @return Extended Master Key
*/
fn master_seed_to_master_key(seed: &[u8; 64]) -> Result<[u8; 64]> {
    // Prepare the extended master key (Master Key + Master Chain Code)
    let mut master_key_ext = [0u8; 64];

    // Allocate a HMAC-SHA512 operation
    match Mac::allocate(AlgorithmId::HmacSha512, 512) 
    {
        Err(_e) => {
            return Err(Error::new(ErrorKind::BadState));
        }
        Ok(mac) => {
            // Allocate a transient object to store the key
            match TransientObject::allocate(TransientObjectType::HmacSha512, 512) {
                Err(_e) => {
                    return Err(Error::new(ErrorKind::BadState));
                }
                Ok(mut key) => {
                    // Convert the string "Bitcoin seed" to a byte array of 64 bytes
                    let mut btn = vec![0u8; 64];
                    btn[0] = 'B' as u8;
                    btn[1] = 'i' as u8;
                    btn[2] = 't' as u8;
                    btn[3] = 'c' as u8;
                    btn[4] = 'o' as u8;
                    btn[5] = 'i' as u8;
                    btn[6] = 'n' as u8;
                    btn[7] = ' ' as u8;
                    btn[8] = 's' as u8;
                    btn[9] = 'e' as u8;
                    btn[10] = 'e' as u8;
                    btn[11] = 'd' as u8;
                    let attr = AttributeMemref::from_ref(AttributeId::SecretValue, &btn);
                    // Populate the key attributes
                    key.populate(&[attr.into()])?;
                    // Set the key in the HMAC operation
                    mac.set_key(&key)?;
                }
            }
            // Initialize the HMAC operation
            mac.init(&[0u8; 0]);

            // Update the HMAC operation with the seed
            mac.update(&seed.to_vec());

            // Compute the final HMAC operation and extract the master key and master chain code
            mac.compute_final(&[0u8; 0], &mut master_key_ext)?;
        }
    }
    // Return the extended master key
    Ok(master_key_ext)
}

/**
 * @brief Verify if the master key exists
 * @return Result
*/
fn check_if_master_key_exist() -> Result<()> {
    // Define the object identifier
    let mut master_key_id = vec![MASTER_KEY_ID; 8];

    // Check if the master key exists
    match PersistentObject::open(ObjectStorageConstants::Private, &mut master_key_id, DataFlag::ACCESS_READ) {
        // If the master key exists, close the object and return Ok
        Ok(mut _obj) => return Ok(()),
        // If the master key does not exist, return an error
        Err(_e) => return Err(Error::new(ErrorKind::ItemNotFound))
    }
}

/**
 * @brief Read the master key, if it exists
 * @return Master Key
*/
fn read_master_key() -> Result<[u8; 64]> {
    // Prepare the extended master key (Master Key + Master Chain Code)
    let mut master_key_ext = [0u8; 64];   

    // Define the object identifier
    let mut master_key_id = vec![MASTER_KEY_ID; 8];

    // Open the master key, if it exists
    match PersistentObject::open(ObjectStorageConstants::Private, &mut master_key_id, DataFlag::ACCESS_READ) {
        // If the master key does not exist, return an error
        Err(_e) => {
            trace_println!("Error opening the master key");
            return Err(Error::new(ErrorKind::ItemNotFound));
        }
        // If the master key exists, contiue
        Ok(obj) => {
            match obj.read(&mut master_key_ext) {
                Err(_e) => return Err(Error::new(ErrorKind::AccessDenied)),
                Ok(_size) => return Ok(master_key_ext)
            }
        }
    }
}

/**
 * @brief Generate a private child key
 * @param level The level of the key (0: master, 1: first child, 2: second child, ...)
 * @param The index of the key (0: first sibbling, 1: second sibbling, ...)
 * @return Private Child Key
*/
fn generate_private_child_key(level: u32, index: u32) -> Result<[u8; 32]> {
    // Prepare the extended master key (Master Key + Master Chain Code)
    let mut master_key_ext = [0u8; 64];   
    let mut mac_final = [0u8; 64];
    let mut child_private_key = [0u8; 32];

    // If the level is 0, the parent private key is the master key
    // Also, as the level 0 is the most critical one, to ensure a higher level of security the private child key
    // will be generated from the private parent key and not from the public parent key (Hardened derivation)
    if level == CKD_LEVEL_0 
    {
        // Read the master key
        match read_master_key() {
            Err(e) => return Err(e),
            Ok(master) => { master_key_ext = master; }
        }
    }

    // Allocate a HMAC-SHA512 operation
    match Mac::allocate(AlgorithmId::HmacSha512, 512) 
    {
        Err(_e) => return Err(Error::new(ErrorKind::BadState)),
        Ok(mac) => 
        {
            // Allocate a transient object to store the key
            match TransientObject::allocate(TransientObjectType::HmacSha512, 512) {
                Err(_e) => {
                    trace_println!("Error allocating the transient object");
                    return Err(Error::new(ErrorKind::BadState));
                }
                Ok(mut key) => {
                    // Create the attribute with the parent chain code (parent chain code is the key)
                    let attr = AttributeMemref::from_ref(AttributeId::SecretValue, &master_key_ext[32..64]);
                    // Populate the key attributes
                    key.populate(&[attr.into()])?;
                    // Set the key in the HMAC operation
                    mac.set_key(&key)?;
                }
            }
            // Initialize the HMAC operation
            mac.init(&[0u8; 0]);

            // Prepare the message (0x00 || parent private key || index)
            let message = [[0u8; 1].to_vec(), master_key_ext[0..32].to_vec(), index.to_be_bytes().to_vec()].concat();

            // Update the HMAC operation with the message (parent private key || index)
            mac.update(&message);

            // Compute the final HMAC operation and extract the master key and master chain code
            mac.compute_final(&[0u8; 0], &mut mac_final)?;
        }
    }

    // Extract the left and right part of the HMAC-SHA512 operation
    let i_l = &mac_final[0..32];
    let i_r = &mac_final[32..64];    // Private child Chain Code

    // Convert to a 512-bit unsigned integer the parent private key
    let k_child_u512 = U512::from_big_endian(&master_key_ext[0..32]);
    trace_println!("Parent private key base16: {:?}", hex::encode(&master_key_ext[0..32]));
    trace_println!("Parent private Chain Code base16: {:?}", hex::encode(&master_key_ext[32..64]));

    // Convert to a 512-bit unsigned integer the left part of the HMAC-SHA512 operation
    let i_l_u512 = U512::from_big_endian(&i_l);

    // Convert to a 512-bit unsigned integer the order of the curve
    let curve_order = U512::from_big_endian(&CURVE_ORDER);

    // Sum the left part of the HMAC-SHA512 operation with the parent private key
    let (res, _cy) = k_child_u512.overflowing_add(i_l_u512);                

    // If the i_l is greater than or equal to the order of the curve, return an error
    if i_l_u512.cmp(&curve_order) == core::cmp::Ordering::Greater || i_l_u512.cmp(&curve_order) == core::cmp::Ordering::Equal {
        trace_println!("ERROR: i_l >= curve_order");
        return Err(Error::new(ErrorKind::BadState));
    }

    // If [parse256(IL) + kpar] mod CURVE_ORDER = 0 (order is a prime number, so the modulo operation is the equal)
    if res.cmp(&curve_order) == core::cmp::Ordering::Equal {
        trace_println!("ERROR: Private key is zero");
        return Err(Error::new(ErrorKind::BadState));
    }

    // Create a 256-bit unsigned integer with the value 0 that will be used to strore the child private key
    let mut child_private_key_u256 = U256::zero();

    // Perform the modulo operation with the order of the curve
    if res >= curve_order {
        child_private_key_u256 = U256::from(res.sub(curve_order));
    }
    else {
        child_private_key_u256 = U256::from(res);
    }

    // Convert the child private key to a 32-byte array
    child_private_key_u256.to_big_endian(&mut child_private_key);

    // Print some debug information
    trace_println!("Child Private Key: {:?}", hex::encode(child_private_key));
    trace_println!("Child Chain Code: {:?}", hex::encode(i_r));

    Ok(child_private_key)

}

/**
 * @brief Generate a public key from a private key (compressed format)
 * @param private_key specifies the private Key
 * @return Publick Key and version
*/
fn generate_public_key_compressed(private_key: [u8; 32]) -> Result<[u8; 33]> {
    // Create the Child Public Key from the Child Private Key (compressed format - 33 bytes)
    let secp = Secp256k1::new();

    // Convert the private key
    let cprvk = SecretKey::from_slice(&private_key).expect("32 bytes, within curve order");

    // Generate the public key compressed format
    let cpubk = PublicKey::from_secret_key(&secp, &cprvk);

    // Convert the public key to a string
    let public_key_str = PublicKey::to_string(&cpubk);

    // Convert the public key to a byte array
    let mut public_key = [0u8; 33];
    let aux = hex::decode(public_key_str.clone()).unwrap();
    let mut i = 0;
    for byte in aux {
        public_key[i] = byte;
        i = i + 1;
    }

    // Print some debug information
    trace_println!("Child Public Key: {}", public_key_str);

    // Return the public key
    Ok(public_key)
}

/**
 * @brief Generate a public key from a private key (uncompressed format)
 * @param private_key specifies the private Key
 * @return Publick Key and version
*/
fn generate_public_key_uncompressed(private_key: [u8; 32]) -> Result<[u8; 65]> {
    // Create the Child Public Key from the Child Private Key (compressed format - 33 bytes)
    let secp = Secp256k1::new();

    // Convert the private key
    let cprvk = SecretKey::from_slice(&private_key).expect("32 bytes, within curve order");

    // Generate the public key compressed format
    let cpubk = PublicKey::from_secret_key(&secp, &cprvk);

    // Covert the public key to a uncompressed format
    let cpubk_uncompressed: [u8; 65] = cpubk.serialize_uncompressed();

    // Print some debug information
    trace_println!("Child Public Key uncompressed: {}", hex::encode(&cpubk_uncompressed));

    // Return the public key in uncompressed format
    Ok(cpubk_uncompressed)
}

/**
 * @brief This function generates a bitcoin address from a public key
 * @param public_key The public key
 * @param addr_type The address type (true for real bitcoin address, false for testnet address)
 * @return The bitcoin address
*/
fn generate_bitcoin_address(public_key: [u8; 33]) -> Result<[u8; 20]> {
    // First stage: SHA256 operation
    let mut sha256_hash = [0u8; 32];
    
    // Allocate a SHA256 operation
    match Digest::allocate(AlgorithmId::Sha256) 
    {
        Err(_e) => return Err(Error::new(ErrorKind::BadState)),
        Ok(sha256) => {
            match sha256.do_final(&public_key, &mut sha256_hash)
            {
                Err(_e) => return Err(Error::new(ErrorKind::BadState)),
                Ok(n) => trace_println!("First stage of the SHA256 operation completed with: {} bytes", n)
            }
        }
    }

    // Create a RIPEMD160 operation
    let mut ripemd160 = Ripemd160::new();

    // Update the RIPEMD160 operation with the SHA256 hash
    ripemd160.update(&sha256_hash);

    // Get the final RIPEMD160 result
    let ripemd160_hash = ripemd160.finalize();

    // Print some debug information
    trace_println!("Second stage RIPEMD160 result: {:?}", ripemd160_hash);

    // Return the RIPEMD160 result (Public Key Double Hash)
    Ok(ripemd160_hash.into())

}

/**
 * @brief This function generates a bitcoin address in the base58check format
 * @param ripemd160_hash specifies the public key double hash
 * @param addr_type specifies the address type (true for real bitcoin address, false for testnet address)
 * @return The bitcoin address in base58check format
*/
fn base_58_check_encode(ripemd160_hash: [u8; 20], addr_type: bool) -> Result<Vec<u8>>
{
    // Third stage: SHA256 operation
    let mut sha256_hash2 = [0u8; 32];

    // Fourth stage: SHA256 operation
    let mut sha256_hash3 = [0u8; 32];

    // Create a prefix for the address
    let mut prefix: [u8; 1] = [0x00];
    // Testnet Address: 0x6F
    if addr_type == false {
        prefix = [0x6F];
    }

    // Allocate a SHA256 operation
    match Digest::allocate(AlgorithmId::Sha256) 
    {
        Err(_e) => return Err(Error::new(ErrorKind::BadState)),
        Ok(sha256) => {
            let ripemd160_in = [prefix.to_vec(), ripemd160_hash.to_vec()].concat();

            match sha256.do_final(&ripemd160_in, &mut sha256_hash2)
            {
                Err(_e) => return Err(Error::new(ErrorKind::BadState)),
                Ok(n) => trace_println!("Third stage of the SHA256 operation completed with: {} bytes", n)
            }
        }
    }

    // Allocate a SHA256 operation
    match Digest::allocate(AlgorithmId::Sha256) 
    {
        Err(_e) => return Err(Error::new(ErrorKind::BadState)),
        Ok(sha256) => {
            match sha256.do_final(&sha256_hash2, &mut sha256_hash3)
            {
                Err(_e) => return Err(Error::new(ErrorKind::BadState)),
                Ok(n) => trace_println!("Four stage of the SHA256 operation completed with: {} bytes", n)
            }
        }
    }

    // Compute the Bitcoin address
    let address = [prefix.to_vec(), ripemd160_hash.to_vec(), sha256_hash3[0..4].to_vec()].concat();

    // Print some debug information
    let encoded_address = hex::encode(&address);
    trace_println!("Bitcoin Address: {}", encoded_address);
    trace_println!("Bitcoin Address base58: {}", bs58::encode(&address).into_string());

    // Return the Bitcoin address
    Ok(address)
}

/**
 * @brief Sign and verify a message
 * @param private_key specifies the private key to sign the message
 * @param public_key specifies the public key to verify the message
 * @param message specifies the message to sign and verify
 * @return The signature
*/
fn sign(private_key: [u8; 32], public_key: [u8; 33], message: &[u8]) -> Result<Vec<u8>>
{
    // SHA256 operation
    let mut sha256_hash = [0u8; 32];
        
    // Allocate a SHA256 operation
    match Digest::allocate(AlgorithmId::Sha256) 
    {
        Err(_e) => {
            trace_println!("Error allocating the SHA256 operation");
            return Err(Error::new(ErrorKind::BadState));
        }
        Ok(sha256) => {
            match sha256.do_final(message, &mut sha256_hash)
            {
                Err(_e) => {
                    trace_println!("Error performing the SHA256 operation");
                    return Err(Error::new(ErrorKind::BadState));
                }
                Ok(n) => trace_println!("SHA256 operation completed with: {} bytes", n)
            }
        }
    }

    trace_println!("Message Digested: {}", hex::encode(&sha256_hash));

    // Convert the digested message to a Message struct
    let msg = Message::from_slice(&sha256_hash).expect("32 bytes");

    // Create a new Secp256k1 context
    let secp = Secp256k1::new();

    // Convert the private key to a SecretKey struct
    let priv_key = SecretKey::from_slice(&private_key).expect("32 bytes, within curve order");

    // Convert the public key to a PublicKey struct
    let pub_key = PublicKey::from_slice(&public_key).expect("33 bytes, within curve order");

    // Sign the message
    let signature = secp.sign_ecdsa(&msg, &priv_key);

    // Verify the signature
    if secp.verify_ecdsa(&msg, &signature, &pub_key).is_ok()
    {
        trace_println!("Signature verified");
    }
    else
    {
        trace_println!("Signature verification failed");
    }

    // Convert the signature to a DER format
    let der_signature = signature.serialize_der().to_vec();

    Ok(der_signature)

}

// TA configurations
const TA_FLAGS: u32 = 0;
const TA_DATA_SIZE: u32 = 32 * 1024;
const TA_STACK_SIZE: u32 = 1024 * 1024;
const TA_VERSION: &[u8] = b"0.1\0";
const TA_DESCRIPTION: &[u8] = b"This is a hello world example.\0";
const EXT_PROP_VALUE_1: &[u8] = b"Hello World TA\0";
const EXT_PROP_VALUE_2: u32 = 0x0010;
const TRACE_LEVEL: i32 = 4;
const TRACE_EXT_PREFIX: &[u8] = b"TA\0";
const TA_FRAMEWORK_STACK_SIZE: u32 = 2048;

include!(concat!(env!("OUT_DIR"), "/user_ta_header.rs"));

// BIP39 English word list
const BIP39_EN_WORDS: [&str; 2048] = [
"abandon",
"ability",
"able",
"about",
"above",
"absent",
"absorb",
"abstract",
"absurd",
"abuse",
"access",
"accident",
"account",
"accuse",
"achieve",
"acid",
"acoustic",
"acquire",
"across",
"act",
"action",
"actor",
"actress",
"actual",
"adapt",
"add",
"addict",
"address",
"adjust",
"admit",
"adult",
"advance",
"advice",
"aerobic",
"affair",
"afford",
"afraid",
"again",
"age",
"agent",
"agree",
"ahead",
"aim",
"air",
"airport",
"aisle",
"alarm",
"album",
"alcohol",
"alert",
"alien",
"all",
"alley",
"allow",
"almost",
"alone",
"alpha",
"already",
"also",
"alter",
"always",
"amateur",
"amazing",
"among",
"amount",
"amused",
"analyst",
"anchor",
"ancient",
"anger",
"angle",
"angry",
"animal",
"ankle",
"announce",
"annual",
"another",
"answer",
"antenna",
"antique",
"anxiety",
"any",
"apart",
"apology",
"appear",
"apple",
"approve",
"april",
"arch",
"arctic",
"area",
"arena",
"argue",
"arm",
"armed",
"armor",
"army",
"around",
"arrange",
"arrest",
"arrive",
"arrow",
"art",
"artefact",
"artist",
"artwork",
"ask",
"aspect",
"assault",
"asset",
"assist",
"assume",
"asthma",
"athlete",
"atom",
"attack",
"attend",
"attitude",
"attract",
"auction",
"audit",
"august",
"aunt",
"author",
"auto",
"autumn",
"average",
"avocado",
"avoid",
"awake",
"aware",
"away",
"awesome",
"awful",
"awkward",
"axis",
"baby",
"bachelor",
"bacon",
"badge",
"bag",
"balance",
"balcony",
"ball",
"bamboo",
"banana",
"banner",
"bar",
"barely",
"bargain",
"barrel",
"base",
"basic",
"basket",
"battle",
"beach",
"bean",
"beauty",
"because",
"become",
"beef",
"before",
"begin",
"behave",
"behind",
"believe",
"below",
"belt",
"bench",
"benefit",
"best",
"betray",
"better",
"between",
"beyond",
"bicycle",
"bid",
"bike",
"bind",
"biology",
"bird",
"birth",
"bitter",
"black",
"blade",
"blame",
"blanket",
"blast",
"bleak",
"bless",
"blind",
"blood",
"blossom",
"blouse",
"blue",
"blur",
"blush",
"board",
"boat",
"body",
"boil",
"bomb",
"bone",
"bonus",
"book",
"boost",
"border",
"boring",
"borrow",
"boss",
"bottom",
"bounce",
"box",
"boy",
"bracket",
"brain",
"brand",
"brass",
"brave",
"bread",
"breeze",
"brick",
"bridge",
"brief",
"bright",
"bring",
"brisk",
"broccoli",
"broken",
"bronze",
"broom",
"brother",
"brown",
"brush",
"bubble",
"buddy",
"budget",
"buffalo",
"build",
"bulb",
"bulk",
"bullet",
"bundle",
"bunker",
"burden",
"burger",
"burst",
"bus",
"business",
"busy",
"butter",
"buyer",
"buzz",
"cabbage",
"cabin",
"cable",
"cactus",
"cage",
"cake",
"call",
"calm",
"camera",
"camp",
"can",
"canal",
"cancel",
"candy",
"cannon",
"canoe",
"canvas",
"canyon",
"capable",
"capital",
"captain",
"car",
"carbon",
"card",
"cargo",
"carpet",
"carry",
"cart",
"case",
"cash",
"casino",
"castle",
"casual",
"cat",
"catalog",
"catch",
"category",
"cattle",
"caught",
"cause",
"caution",
"cave",
"ceiling",
"celery",
"cement",
"census",
"century",
"cereal",
"certain",
"chair",
"chalk",
"champion",
"change",
"chaos",
"chapter",
"charge",
"chase",
"chat",
"cheap",
"check",
"cheese",
"chef",
"cherry",
"chest",
"chicken",
"chief",
"child",
"chimney",
"choice",
"choose",
"chronic",
"chuckle",
"chunk",
"churn",
"cigar",
"cinnamon",
"circle",
"citizen",
"city",
"civil",
"claim",
"clap",
"clarify",
"claw",
"clay",
"clean",
"clerk",
"clever",
"click",
"client",
"cliff",
"climb",
"clinic",
"clip",
"clock",
"clog",
"close",
"cloth",
"cloud",
"clown",
"club",
"clump",
"cluster",
"clutch",
"coach",
"coast",
"coconut",
"code",
"coffee",
"coil",
"coin",
"collect",
"color",
"column",
"combine",
"come",
"comfort",
"comic",
"common",
"company",
"concert",
"conduct",
"confirm",
"congress",
"connect",
"consider",
"control",
"convince",
"cook",
"cool",
"copper",
"copy",
"coral",
"core",
"corn",
"correct",
"cost",
"cotton",
"couch",
"country",
"couple",
"course",
"cousin",
"cover",
"coyote",
"crack",
"cradle",
"craft",
"cram",
"crane",
"crash",
"crater",
"crawl",
"crazy",
"cream",
"credit",
"creek",
"crew",
"cricket",
"crime",
"crisp",
"critic",
"crop",
"cross",
"crouch",
"crowd",
"crucial",
"cruel",
"cruise",
"crumble",
"crunch",
"crush",
"cry",
"crystal",
"cube",
"culture",
"cup",
"cupboard",
"curious",
"current",
"curtain",
"curve",
"cushion",
"custom",
"cute",
"cycle",
"dad",
"damage",
"damp",
"dance",
"danger",
"daring",
"dash",
"daughter",
"dawn",
"day",
"deal",
"debate",
"debris",
"decade",
"december",
"decide",
"decline",
"decorate",
"decrease",
"deer",
"defense",
"define",
"defy",
"degree",
"delay",
"deliver",
"demand",
"demise",
"denial",
"dentist",
"deny",
"depart",
"depend",
"deposit",
"depth",
"deputy",
"derive",
"describe",
"desert",
"design",
"desk",
"despair",
"destroy",
"detail",
"detect",
"develop",
"device",
"devote",
"diagram",
"dial",
"diamond",
"diary",
"dice",
"diesel",
"diet",
"differ",
"digital",
"dignity",
"dilemma",
"dinner",
"dinosaur",
"direct",
"dirt",
"disagree",
"discover",
"disease",
"dish",
"dismiss",
"disorder",
"display",
"distance",
"divert",
"divide",
"divorce",
"dizzy",
"doctor",
"document",
"dog",
"doll",
"dolphin",
"domain",
"donate",
"donkey",
"donor",
"door",
"dose",
"double",
"dove",
"draft",
"dragon",
"drama",
"drastic",
"draw",
"dream",
"dress",
"drift",
"drill",
"drink",
"drip",
"drive",
"drop",
"drum",
"dry",
"duck",
"dumb",
"dune",
"during",
"dust",
"dutch",
"duty",
"dwarf",
"dynamic",
"eager",
"eagle",
"early",
"earn",
"earth",
"easily",
"east",
"easy",
"echo",
"ecology",
"economy",
"edge",
"edit",
"educate",
"effort",
"egg",
"eight",
"either",
"elbow",
"elder",
"electric",
"elegant",
"element",
"elephant",
"elevator",
"elite",
"else",
"embark",
"embody",
"embrace",
"emerge",
"emotion",
"employ",
"empower",
"empty",
"enable",
"enact",
"end",
"endless",
"endorse",
"enemy",
"energy",
"enforce",
"engage",
"engine",
"enhance",
"enjoy",
"enlist",
"enough",
"enrich",
"enroll",
"ensure",
"enter",
"entire",
"entry",
"envelope",
"episode",
"equal",
"equip",
"era",
"erase",
"erode",
"erosion",
"error",
"erupt",
"escape",
"essay",
"essence",
"estate",
"eternal",
"ethics",
"evidence",
"evil",
"evoke",
"evolve",
"exact",
"example",
"excess",
"exchange",
"excite",
"exclude",
"excuse",
"execute",
"exercise",
"exhaust",
"exhibit",
"exile",
"exist",
"exit",
"exotic",
"expand",
"expect",
"expire",
"explain",
"expose",
"express",
"extend",
"extra",
"eye",
"eyebrow",
"fabric",
"face",
"faculty",
"fade",
"faint",
"faith",
"fall",
"false",
"fame",
"family",
"famous",
"fan",
"fancy",
"fantasy",
"farm",
"fashion",
"fat",
"fatal",
"father",
"fatigue",
"fault",
"favorite",
"feature",
"february",
"federal",
"fee",
"feed",
"feel",
"female",
"fence",
"festival",
"fetch",
"fever",
"few",
"fiber",
"fiction",
"field",
"figure",
"file",
"film",
"filter",
"final",
"find",
"fine",
"finger",
"finish",
"fire",
"firm",
"first",
"fiscal",
"fish",
"fit",
"fitness",
"fix",
"flag",
"flame",
"flash",
"flat",
"flavor",
"flee",
"flight",
"flip",
"float",
"flock",
"floor",
"flower",
"fluid",
"flush",
"fly",
"foam",
"focus",
"fog",
"foil",
"fold",
"follow",
"food",
"foot",
"force",
"forest",
"forget",
"fork",
"fortune",
"forum",
"forward",
"fossil",
"foster",
"found",
"fox",
"fragile",
"frame",
"frequent",
"fresh",
"friend",
"fringe",
"frog",
"front",
"frost",
"frown",
"frozen",
"fruit",
"fuel",
"fun",
"funny",
"furnace",
"fury",
"future",
"gadget",
"gain",
"galaxy",
"gallery",
"game",
"gap",
"garage",
"garbage",
"garden",
"garlic",
"garment",
"gas",
"gasp",
"gate",
"gather",
"gauge",
"gaze",
"general",
"genius",
"genre",
"gentle",
"genuine",
"gesture",
"ghost",
"giant",
"gift",
"giggle",
"ginger",
"giraffe",
"girl",
"give",
"glad",
"glance",
"glare",
"glass",
"glide",
"glimpse",
"globe",
"gloom",
"glory",
"glove",
"glow",
"glue",
"goat",
"goddess",
"gold",
"good",
"goose",
"gorilla",
"gospel",
"gossip",
"govern",
"gown",
"grab",
"grace",
"grain",
"grant",
"grape",
"grass",
"gravity",
"great",
"green",
"grid",
"grief",
"grit",
"grocery",
"group",
"grow",
"grunt",
"guard",
"guess",
"guide",
"guilt",
"guitar",
"gun",
"gym",
"habit",
"hair",
"half",
"hammer",
"hamster",
"hand",
"happy",
"harbor",
"hard",
"harsh",
"harvest",
"hat",
"have",
"hawk",
"hazard",
"head",
"health",
"heart",
"heavy",
"hedgehog",
"height",
"hello",
"helmet",
"help",
"hen",
"hero",
"hidden",
"high",
"hill",
"hint",
"hip",
"hire",
"history",
"hobby",
"hockey",
"hold",
"hole",
"holiday",
"hollow",
"home",
"honey",
"hood",
"hope",
"horn",
"horror",
"horse",
"hospital",
"host",
"hotel",
"hour",
"hover",
"hub",
"huge",
"human",
"humble",
"humor",
"hundred",
"hungry",
"hunt",
"hurdle",
"hurry",
"hurt",
"husband",
"hybrid",
"ice",
"icon",
"idea",
"identify",
"idle",
"ignore",
"ill",
"illegal",
"illness",
"image",
"imitate",
"immense",
"immune",
"impact",
"impose",
"improve",
"impulse",
"inch",
"include",
"income",
"increase",
"index",
"indicate",
"indoor",
"industry",
"infant",
"inflict",
"inform",
"inhale",
"inherit",
"initial",
"inject",
"injury",
"inmate",
"inner",
"innocent",
"input",
"inquiry",
"insane",
"insect",
"inside",
"inspire",
"install",
"intact",
"interest",
"into",
"invest",
"invite",
"involve",
"iron",
"island",
"isolate",
"issue",
"item",
"ivory",
"jacket",
"jaguar",
"jar",
"jazz",
"jealous",
"jeans",
"jelly",
"jewel",
"job",
"join",
"joke",
"journey",
"joy",
"judge",
"juice",
"jump",
"jungle",
"junior",
"junk",
"just",
"kangaroo",
"keen",
"keep",
"ketchup",
"key",
"kick",
"kid",
"kidney",
"kind",
"kingdom",
"kiss",
"kit",
"kitchen",
"kite",
"kitten",
"kiwi",
"knee",
"knife",
"knock",
"know",
"lab",
"label",
"labor",
"ladder",
"lady",
"lake",
"lamp",
"language",
"laptop",
"large",
"later",
"latin",
"laugh",
"laundry",
"lava",
"law",
"lawn",
"lawsuit",
"layer",
"lazy",
"leader",
"leaf",
"learn",
"leave",
"lecture",
"left",
"leg",
"legal",
"legend",
"leisure",
"lemon",
"lend",
"length",
"lens",
"leopard",
"lesson",
"letter",
"level",
"liar",
"liberty",
"library",
"license",
"life",
"lift",
"light",
"like",
"limb",
"limit",
"link",
"lion",
"liquid",
"list",
"little",
"live",
"lizard",
"load",
"loan",
"lobster",
"local",
"lock",
"logic",
"lonely",
"long",
"loop",
"lottery",
"loud",
"lounge",
"love",
"loyal",
"lucky",
"luggage",
"lumber",
"lunar",
"lunch",
"luxury",
"lyrics",
"machine",
"mad",
"magic",
"magnet",
"maid",
"mail",
"main",
"major",
"make",
"mammal",
"man",
"manage",
"mandate",
"mango",
"mansion",
"manual",
"maple",
"marble",
"march",
"margin",
"marine",
"market",
"marriage",
"mask",
"mass",
"master",
"match",
"material",
"math",
"matrix",
"matter",
"maximum",
"maze",
"meadow",
"mean",
"measure",
"meat",
"mechanic",
"medal",
"media",
"melody",
"melt",
"member",
"memory",
"mention",
"menu",
"mercy",
"merge",
"merit",
"merry",
"mesh",
"message",
"metal",
"method",
"middle",
"midnight",
"milk",
"million",
"mimic",
"mind",
"minimum",
"minor",
"minute",
"miracle",
"mirror",
"misery",
"miss",
"mistake",
"mix",
"mixed",
"mixture",
"mobile",
"model",
"modify",
"mom",
"moment",
"monitor",
"monkey",
"monster",
"month",
"moon",
"moral",
"more",
"morning",
"mosquito",
"mother",
"motion",
"motor",
"mountain",
"mouse",
"move",
"movie",
"much",
"muffin",
"mule",
"multiply",
"muscle",
"museum",
"mushroom",
"music",
"must",
"mutual",
"myself",
"mystery",
"myth",
"naive",
"name",
"napkin",
"narrow",
"nasty",
"nation",
"nature",
"near",
"neck",
"need",
"negative",
"neglect",
"neither",
"nephew",
"nerve",
"nest",
"net",
"network",
"neutral",
"never",
"news",
"next",
"nice",
"night",
"noble",
"noise",
"nominee",
"noodle",
"normal",
"north",
"nose",
"notable",
"note",
"nothing",
"notice",
"novel",
"now",
"nuclear",
"number",
"nurse",
"nut",
"oak",
"obey",
"object",
"oblige",
"obscure",
"observe",
"obtain",
"obvious",
"occur",
"ocean",
"october",
"odor",
"off",
"offer",
"office",
"often",
"oil",
"okay",
"old",
"olive",
"olympic",
"omit",
"once",
"one",
"onion",
"online",
"only",
"open",
"opera",
"opinion",
"oppose",
"option",
"orange",
"orbit",
"orchard",
"order",
"ordinary",
"organ",
"orient",
"original",
"orphan",
"ostrich",
"other",
"outdoor",
"outer",
"output",
"outside",
"oval",
"oven",
"over",
"own",
"owner",
"oxygen",
"oyster",
"ozone",
"pact",
"paddle",
"page",
"pair",
"palace",
"palm",
"panda",
"panel",
"panic",
"panther",
"paper",
"parade",
"parent",
"park",
"parrot",
"party",
"pass",
"patch",
"path",
"patient",
"patrol",
"pattern",
"pause",
"pave",
"payment",
"peace",
"peanut",
"pear",
"peasant",
"pelican",
"pen",
"penalty",
"pencil",
"people",
"pepper",
"perfect",
"permit",
"person",
"pet",
"phone",
"photo",
"phrase",
"physical",
"piano",
"picnic",
"picture",
"piece",
"pig",
"pigeon",
"pill",
"pilot",
"pink",
"pioneer",
"pipe",
"pistol",
"pitch",
"pizza",
"place",
"planet",
"plastic",
"plate",
"play",
"please",
"pledge",
"pluck",
"plug",
"plunge",
"poem",
"poet",
"point",
"polar",
"pole",
"police",
"pond",
"pony",
"pool",
"popular",
"portion",
"position",
"possible",
"post",
"potato",
"pottery",
"poverty",
"powder",
"power",
"practice",
"praise",
"predict",
"prefer",
"prepare",
"present",
"pretty",
"prevent",
"price",
"pride",
"primary",
"print",
"priority",
"prison",
"private",
"prize",
"problem",
"process",
"produce",
"profit",
"program",
"project",
"promote",
"proof",
"property",
"prosper",
"protect",
"proud",
"provide",
"public",
"pudding",
"pull",
"pulp",
"pulse",
"pumpkin",
"punch",
"pupil",
"puppy",
"purchase",
"purity",
"purpose",
"purse",
"push",
"put",
"puzzle",
"pyramid",
"quality",
"quantum",
"quarter",
"question",
"quick",
"quit",
"quiz",
"quote",
"rabbit",
"raccoon",
"race",
"rack",
"radar",
"radio",
"rail",
"rain",
"raise",
"rally",
"ramp",
"ranch",
"random",
"range",
"rapid",
"rare",
"rate",
"rather",
"raven",
"raw",
"razor",
"ready",
"real",
"reason",
"rebel",
"rebuild",
"recall",
"receive",
"recipe",
"record",
"recycle",
"reduce",
"reflect",
"reform",
"refuse",
"region",
"regret",
"regular",
"reject",
"relax",
"release",
"relief",
"rely",
"remain",
"remember",
"remind",
"remove",
"render",
"renew",
"rent",
"reopen",
"repair",
"repeat",
"replace",
"report",
"require",
"rescue",
"resemble",
"resist",
"resource",
"response",
"result",
"retire",
"retreat",
"return",
"reunion",
"reveal",
"review",
"reward",
"rhythm",
"rib",
"ribbon",
"rice",
"rich",
"ride",
"ridge",
"rifle",
"right",
"rigid",
"ring",
"riot",
"ripple",
"risk",
"ritual",
"rival",
"river",
"road",
"roast",
"robot",
"robust",
"rocket",
"romance",
"roof",
"rookie",
"room",
"rose",
"rotate",
"rough",
"round",
"route",
"royal",
"rubber",
"rude",
"rug",
"rule",
"run",
"runway",
"rural",
"sad",
"saddle",
"sadness",
"safe",
"sail",
"salad",
"salmon",
"salon",
"salt",
"salute",
"same",
"sample",
"sand",
"satisfy",
"satoshi",
"sauce",
"sausage",
"save",
"say",
"scale",
"scan",
"scare",
"scatter",
"scene",
"scheme",
"school",
"science",
"scissors",
"scorpion",
"scout",
"scrap",
"screen",
"script",
"scrub",
"sea",
"search",
"season",
"seat",
"second",
"secret",
"section",
"security",
"seed",
"seek",
"segment",
"select",
"sell",
"seminar",
"senior",
"sense",
"sentence",
"series",
"service",
"session",
"settle",
"setup",
"seven",
"shadow",
"shaft",
"shallow",
"share",
"shed",
"shell",
"sheriff",
"shield",
"shift",
"shine",
"ship",
"shiver",
"shock",
"shoe",
"shoot",
"shop",
"short",
"shoulder",
"shove",
"shrimp",
"shrug",
"shuffle",
"shy",
"sibling",
"sick",
"side",
"siege",
"sight",
"sign",
"silent",
"silk",
"silly",
"silver",
"similar",
"simple",
"since",
"sing",
"siren",
"sister",
"situate",
"six",
"size",
"skate",
"sketch",
"ski",
"skill",
"skin",
"skirt",
"skull",
"slab",
"slam",
"sleep",
"slender",
"slice",
"slide",
"slight",
"slim",
"slogan",
"slot",
"slow",
"slush",
"small",
"smart",
"smile",
"smoke",
"smooth",
"snack",
"snake",
"snap",
"sniff",
"snow",
"soap",
"soccer",
"social",
"sock",
"soda",
"soft",
"solar",
"soldier",
"solid",
"solution",
"solve",
"someone",
"song",
"soon",
"sorry",
"sort",
"soul",
"sound",
"soup",
"source",
"south",
"space",
"spare",
"spatial",
"spawn",
"speak",
"special",
"speed",
"spell",
"spend",
"sphere",
"spice",
"spider",
"spike",
"spin",
"spirit",
"split",
"spoil",
"sponsor",
"spoon",
"sport",
"spot",
"spray",
"spread",
"spring",
"spy",
"square",
"squeeze",
"squirrel",
"stable",
"stadium",
"staff",
"stage",
"stairs",
"stamp",
"stand",
"start",
"state",
"stay",
"steak",
"steel",
"stem",
"step",
"stereo",
"stick",
"still",
"sting",
"stock",
"stomach",
"stone",
"stool",
"story",
"stove",
"strategy",
"street",
"strike",
"strong",
"struggle",
"student",
"stuff",
"stumble",
"style",
"subject",
"submit",
"subway",
"success",
"such",
"sudden",
"suffer",
"sugar",
"suggest",
"suit",
"summer",
"sun",
"sunny",
"sunset",
"super",
"supply",
"supreme",
"sure",
"surface",
"surge",
"surprise",
"surround",
"survey",
"suspect",
"sustain",
"swallow",
"swamp",
"swap",
"swarm",
"swear",
"sweet",
"swift",
"swim",
"swing",
"switch",
"sword",
"symbol",
"symptom",
"syrup",
"system",
"table",
"tackle",
"tag",
"tail",
"talent",
"talk",
"tank",
"tape",
"target",
"task",
"taste",
"tattoo",
"taxi",
"teach",
"team",
"tell",
"ten",
"tenant",
"tennis",
"tent",
"term",
"test",
"text",
"thank",
"that",
"theme",
"then",
"theory",
"there",
"they",
"thing",
"this",
"thought",
"three",
"thrive",
"throw",
"thumb",
"thunder",
"ticket",
"tide",
"tiger",
"tilt",
"timber",
"time",
"tiny",
"tip",
"tired",
"tissue",
"title",
"toast",
"tobacco",
"today",
"toddler",
"toe",
"together",
"toilet",
"token",
"tomato",
"tomorrow",
"tone",
"tongue",
"tonight",
"tool",
"tooth",
"top",
"topic",
"topple",
"torch",
"tornado",
"tortoise",
"toss",
"total",
"tourist",
"toward",
"tower",
"town",
"toy",
"track",
"trade",
"traffic",
"tragic",
"train",
"transfer",
"trap",
"trash",
"travel",
"tray",
"treat",
"tree",
"trend",
"trial",
"tribe",
"trick",
"trigger",
"trim",
"trip",
"trophy",
"trouble",
"truck",
"true",
"truly",
"trumpet",
"trust",
"truth",
"try",
"tube",
"tuition",
"tumble",
"tuna",
"tunnel",
"turkey",
"turn",
"turtle",
"twelve",
"twenty",
"twice",
"twin",
"twist",
"two",
"type",
"typical",
"ugly",
"umbrella",
"unable",
"unaware",
"uncle",
"uncover",
"under",
"undo",
"unfair",
"unfold",
"unhappy",
"uniform",
"unique",
"unit",
"universe",
"unknown",
"unlock",
"until",
"unusual",
"unveil",
"update",
"upgrade",
"uphold",
"upon",
"upper",
"upset",
"urban",
"urge",
"usage",
"use",
"used",
"useful",
"useless",
"usual",
"utility",
"vacant",
"vacuum",
"vague",
"valid",
"valley",
"valve",
"van",
"vanish",
"vapor",
"various",
"vast",
"vault",
"vehicle",
"velvet",
"vendor",
"venture",
"venue",
"verb",
"verify",
"version",
"very",
"vessel",
"veteran",
"viable",
"vibrant",
"vicious",
"victory",
"video",
"view",
"village",
"vintage",
"violin",
"virtual",
"virus",
"visa",
"visit",
"visual",
"vital",
"vivid",
"vocal",
"voice",
"void",
"volcano",
"volume",
"vote",
"voyage",
"wage",
"wagon",
"wait",
"walk",
"wall",
"walnut",
"want",
"warfare",
"warm",
"warrior",
"wash",
"wasp",
"waste",
"water",
"wave",
"way",
"wealth",
"weapon",
"wear",
"weasel",
"weather",
"web",
"wedding",
"weekend",
"weird",
"welcome",
"west",
"wet",
"whale",
"what",
"wheat",
"wheel",
"when",
"where",
"whip",
"whisper",
"wide",
"width",
"wife",
"wild",
"will",
"win",
"window",
"wine",
"wing",
"wink",
"winner",
"winter",
"wire",
"wisdom",
"wise",
"wish",
"witness",
"wolf",
"woman",
"wonder",
"wood",
"wool",
"word",
"work",
"world",
"worry",
"worth",
"wrap",
"wreck",
"wrestle",
"wrist",
"write",
"wrong",
"yard",
"year",
"yellow",
"you",
"young",
"youth",
"zebra",
"zero",
"zone",
"zoo",
];