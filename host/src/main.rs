use optee_teec::{Context, Operation, ParamType, Session, Uuid, ParamNone, ParamValue, ParamTmpRef};     // Use the optee_teec crate
use proto::{UUID, Command, bitcoin_transaction};                                                        // Use the proto crate 
use bitcoin_transaction::{Transaction, InputTransaction, OutputTransaction, BaseOutputTransaction};     // Use the bitcoin_transaction crate
use std::env;                                                                                           // Use the std crate to access the environment variables
use hex;                                                                                                // Use the hex crate to display the Bitcoin address

/**
 * @brief Helps the user to use the Application.
 * @details Prints the usage of the Application.
 */
fn help() 
{
    println!("Usage: ./bitcoin_wallet <option> <command> <PIN> [-a <mnemonic> <account_id>]");
    println!("Commands:");
    println!("1 - Check if there is a master key");
    println!("2 - Generate a new master key");
    println!("3 - From mnemonic to master key");
    println!("4 - Erase master key");
    println!("5 - Issue transaction");
    println!("6 - Get Bitcoin address");

    println!("Usage:");
    println!("1 - ./bitcoin_wallet 1 <PIN>");
    println!("2 - ./bitcoin_wallet 2 <PIN>");
    println!("3 - ./bitcoin_wallet 3 <PIN> -a <mnemonic>");
    println!("4 - ./bitcoin_wallet 4 <PIN>");
    println!("5 - ./bitcoin_wallet 5 <PIN> -a <account_id>");
    println!("6 - ./bitcoin_wallet 6 <PIN> -a <account_id>");
}

/**
 * @brief Checks the arguments of the Application.
 * @return The command, the PIN, the mnemonic and the account ID.
 */
fn check_args() -> Result<(Command,u32,String,u8), &'static str> 
{
    let args: Vec<String> = env::args().collect();
    let mut mnemonic: String = "".to_string();
    let mut account_id: u8 = 0;

    if args.len() < 3 || args.len() > 5
    {
        return Err("Invalid number of arguments");
    }

    let command: Command = Command::from(args[1].parse::<u32>().expect("Invalid command"));
    let pin: u32 = args[2].parse::<u32>().expect("Invalid PIN");

    match command {
        Command::MnemonicToMasterKey => {
            if args.len() != 5
            {
                return Err("Invalid number of arguments");
            }
            if args[3] != "-a"
            {
                return Err("Invalid argument");
            }
            mnemonic = args[4].to_string();
        }
        Command::SignTransaction | Command::GetBitcoinAddress => {
            if args.len() != 5
            {
                return Err("Invalid number of arguments");
            }
            if args[3] != "-a"
            {
                return Err("Invalid argument");
            }
            account_id = args[4].parse::<u8>().expect("Invalid account number");
            if account_id > 9
            {
                return Err("Invalid account number");
            }
        }
        Command::Unknown => return Err("Invalid command"),
        _ => {}
    }
    return Ok((command,pin,mnemonic,account_id));

}

/**
 * @brief Print some information about the Application.
 * @param command specifies the command.
 * @param pin specifies the PIN.
 * @param mnemonic specifies the mnemonic.
 * @param account_id specifies the account ID.
 */
fn print_info(command: &Command, pin: &u32, mnemonic: &str, account_id: &u8) 
{
    println!("Command: {:?}", command);
    println!("PIN: {}", pin);
    println!("Mnemonic: {}", mnemonic);
    println!("Account ID: {}", account_id);
}

/**
 * @brief Checks if the Master Key exists.
 * @param session specifies the session.
 * @param pin specifies the PIN.
 * @param cmd specifies the command.
 * @return Ok() if the Master Key exists, Err(e) otherwise.
 */
fn check_master_key(session: &mut Session, pin: u32, cmd: Command) -> optee_teec::Result<()>
{
    // Send the PIN code to the Trusted Application and check if the Master Key exists
    // a = PIN
    let p0: ParamValue = ParamValue::new(pin, 0, ParamType::ValueInput);

    // Create ethe Operation
    let mut operation = Operation::new(0, p0, ParamNone, ParamNone, ParamNone);

    // Call the Trusted Application    
    match session.invoke_command(cmd as u32, &mut operation) {
        Ok(_) => println!("Master key exists"),
        Err(e) => {
            println!("Masterkey doesn exist");
            println!("Error: {:?}", e);
            return Ok(());
        }
    };
    Ok(())
}

/**
 * @brief Generates a new Master Key.
 * @param session specifies the session.
 * @param pin specifies the PIN.
 * @param cmd specifies the command.
 * @return Ok() if the Master Key is generated, Err(e) otherwise.
 */
fn generate_master_key(session: &mut Session, pin: u32, cmd: Command) -> optee_teec::Result<()>
{
    // Send the PIN code to the Trusted Application
    let p0: ParamValue = ParamValue::new(pin, 0, ParamType::ValueInput);

    // Prepare the mnemonic feedback from the Trusted Application
    let mut mnemonic: [u8; 512] = [0; 512];
    let p1: ParamTmpRef = ParamTmpRef::new_output(&mut mnemonic);

    // Create the Operation
    let mut operation = Operation::new(0, p0, p1, ParamNone, ParamNone);

    // Call the Trusted Application
    match session.invoke_command(cmd as u32, &mut operation) {
        Ok(_) => {
            println!("Mnemonic: {}", String::from_utf8_lossy(&mnemonic));
        }
        Err(e) => {
            println!("Masterkey already exists");
            println!("Error: {:?}", e);
            return Ok(());
        }
    };
    Ok(())
}

/**
 * @brief Derivate the Master Key from a mnemonic.
 * @param session specifies the session.
 * @param pin specifies the PIN.
 * @param cmd specifies the command.
 * @param mnemonic specifies the mnemonic.
 * @return Ok() if the Master Key is generated, Err(e) otherwise.
 */
fn mnemonic_to_master_key(session: &mut Session, pin: u32, cmd: Command, mnemonic: &str) -> optee_teec::Result<()>
{
    // Send the PIN code to the Trusted Application
    let p0: ParamValue = ParamValue::new(pin, 0, ParamType::ValueInput);

    // Send the mnemonic to the Trusted Application
    let p1: ParamTmpRef = ParamTmpRef::new_input(mnemonic.as_bytes());

    // Create the Operation
    let mut operation = Operation::new(0, p0, p1, ParamNone, ParamNone);

    // Call the Trusted Application
    match session.invoke_command(cmd as u32, &mut operation) {
        Ok(_) => {
            println!("Success");
        }
        Err(e) => {
            println!("Cannot derivate master key from mnemonic");
            println!("Error: {:?}", e);
            return Ok(());
        }
    };
    Ok(())

}

/**
 * @brief Erase the Master Key.
 * @param session specifies the session.
 * @param pin specifies the PIN.
 * @param cmd specifies the command.
 * @return Ok() if the Master key was erased successfully, Err(e) otherwise.
 */
fn erase_master_key(session: &mut Session, pin: u32, cmd: Command) -> optee_teec::Result<()>
{
    // Send the PIN code to the Trusted Application
    let p0: ParamValue = ParamValue::new(pin, 0, ParamType::ValueInput);

    // Create the Operation
    let mut operation = Operation::new(0, p0, ParamNone, ParamNone, ParamNone);

    // Call the Trusted Application
    match session.invoke_command(cmd as u32, &mut operation) {
        Ok(_) => {
            println!("Masterkey erased successfully");
        }
        Err(e) => {
            println!("Masterkey doesn't exist");
            println!("Error: {:?}", e);
            return Ok(());
        }
    };
    Ok(())

}

/**
 * @brief Issue a transaction.
 * @param session specifies the session.
 * @param pin specifies the PIN.
 * @param cmd specifies the command.
 * @param account_id specifies the account ID.
 * @return Ok() if the Account exists, Err(e) otherwise.
 */
fn issue_transaction(session: &mut Session, pin: u32, cmd: Command, account_id: u8) -> optee_teec::Result<()>
{    
    let transaction_id = [3u8; 32];
    let index = 0x00;
    let value = 0x0000000001010101;
    let locktime = 0;
    let script_pubkey = vec![0x76, 0xA9, 0x14, 91, 50, 165, 58, 158, 50, 164, 251, 195, 23, 49, 130, 76, 185, 38, 32, 134, 100, 14, 123, 0x88, 0xAC];
    let script_pubkey_cpy = vec![0x76, 0xA9, 0x14, 91, 50, 165, 58, 158, 50, 164, 251, 195, 23, 49, 130, 76, 185, 38, 32, 134, 100, 14, 123, 0x88, 0xAC];

    // Transaction to be signed (will be used the field sigpubkey to send the bitcoin address)
    let ta_transaction = Transaction::new(0x02,
    vec![InputTransaction::new(BaseOutputTransaction { txid: (transaction_id), index: (index) }, 
    script_pubkey, 0xFFFFFFFF)],vec![OutputTransaction::new(value, script_pubkey_cpy)],locktime);

    let d1 = ta_transaction.serialize();

    // Send the PIN code to the Trusted Application
    let p0: ParamValue = ParamValue::new(pin, account_id as u32, ParamType::ValueInput);

    // Send the informations about the transaction to the Trusted Application
    let p1: ParamTmpRef = ParamTmpRef::new_input(&d1);

    // Prepare the signed transaction feedback from the Trusted Application
    let sizes = ta_transaction.get_lengths();
    let mut aux_vector = vec![0u8; 26 + sizes.0 * 159 + sizes.1 * 100];
    let mut signed_transaction = aux_vector.as_mut_slice();
    let p2: ParamTmpRef = ParamTmpRef::new_output(&mut signed_transaction);

    // Create the Operation
    let mut operation = Operation::new(0, p0, p1, p2, ParamNone);

    // Call the Trusted Application
    match session.invoke_command(cmd as u32, &mut operation) {
        Ok(_) => {
            println!("Transaction issued successfully");
            println!("Signed transaction: {:?}", signed_transaction);
            println!("Signed transaction base16: {}", hex::encode(signed_transaction));
        }
        Err(e) => {
            println!("Cannot issue transaction");
            println!("Error: {:?}", e);
            return Ok(());
        }
    };
    Ok(())
}

/**
 * @brief Request a Bitcoin address.
 * @param session specifies the session.
 * @param pin specifies the PIN.
 * @param cmd specifies the command.
 * @param account_id specifies the account ID.
 * @return Ok() if the Account exists, Err(e) otherwise.
 */
fn get_bitcoin_address(session: &mut Session, pin: u32, cmd: Command, account_id: u8) -> optee_teec::Result<()>
{
    // Send the PIN code and account ID to the Trusted Application
    // a = PIN
    // b = account ID
    let p0: ParamValue = ParamValue::new(pin, account_id as u32, ParamType::ValueInput);

    // Prepare the Bitcoin address feedback from the Trusted Application
    let mut address = [0u8; 25];
    let p1: ParamTmpRef = ParamTmpRef::new_output(&mut address);
    
    // Create the Operation
    let mut operation = Operation::new(0, p0, p1, ParamNone, ParamNone);

    // Call the Trusted Application
    match session.invoke_command(cmd as u32, &mut operation) {
        Ok(_) => {
            println!("Bitcoin address: {}", hex::encode(address));
        }
        Err(e) => {
            println!("Get Bitcoin address failed");
            println!("Error: {:?}", e);
            return Ok(());
        }
    };
    Ok(())

}

/**
 * @brief Main function.
 * @return Ok() if the Account exists, Err(e) otherwise.
 */
fn main() -> optee_teec::Result<()> 
{
    // Check the arguments
    let (command, pin, mnemonic, account_id) = match check_args()
    {
        Ok((command, pin, mnemonic, account_id)) => (command, pin, mnemonic, account_id),
        Err(e) => {
            println!("{}",e);
            return Ok(());
        }
    };

    // Print the information
    print_info(&command, &pin, mnemonic.as_str(), &account_id);

    // Create a new context
    let mut context: Context = Context::new()?;

    // Define the UUID (Unique Universal Identifier)
    let uuid: Uuid = Uuid::parse_str(UUID).unwrap();

    // Open a session with the UUID
    let mut session: Session = context.open_session(uuid)?;

    // According to the command, call the corresponding function
    match command
    {
        Command::CheckMasterKey => {
            check_master_key(&mut session, pin, Command::CheckMasterKey)?;
        },
        Command::GenerateMasterKey => {
            generate_master_key(&mut session, pin, Command::GenerateMasterKey)?;
        },
        Command::MnemonicToMasterKey => {
            mnemonic_to_master_key(&mut session, pin, Command::MnemonicToMasterKey, mnemonic.as_str())?;
        },
        Command::EraseMasterKey => {
            erase_master_key(&mut session, pin, Command::EraseMasterKey)?;
        },
        Command::SignTransaction => {
            issue_transaction(&mut session, pin, Command::SignTransaction, account_id)?;
        },
        Command::GetBitcoinAddress => {
            get_bitcoin_address(&mut session, pin, Command::GetBitcoinAddress, account_id)?;
        },
        _ => {
            println!("Invalid command");
            help();
        }
    }

    // Return 
    Ok(())
}
