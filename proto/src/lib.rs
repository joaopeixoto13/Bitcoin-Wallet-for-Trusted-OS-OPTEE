/**
 * @brief Command enum
 * @details This enum is used to identify the command sent by the host, abstracting the command id
*/
#[derive (Debug)]                               // Debug Trait is used to print the enum
pub enum Command {  
    CheckMasterKey = 1,                         // CheckMasterKey command id
    GenerateMasterKey,                          // GenerateMasterKey command id
    MnemonicToMasterKey,                        // MnemonicToMasterKey command id
    EraseMasterKey,                             // EraseMasterKey command id
    SignTransaction,                            // SignTransaction command id
    GetBitcoinAddress,                          // GetBitcoinAddress command id
    Unknown,                                    // Unknown command id
}

/**
 * @brief Implementation of the 'From trait' for the Command enum
 * @details This feature allows to convert a u32 value into a Command enum
*/
impl From<u32> for Command {
    #[inline]
    fn from(value: u32) -> Command {
        match value {
            1 => Command::CheckMasterKey,       // CheckMasterKey command id
            2 => Command::GenerateMasterKey,    // GenerateMasterKey command id
            3 => Command::MnemonicToMasterKey,  // MnemonicToMasterKey command id
            4 => Command::EraseMasterKey,       // EraseMasterKey command id
            5 => Command::SignTransaction,      // SignTransaction command id
            6 => Command::GetBitcoinAddress,    // GetBitcoinAddress command id
            _ => Command::Unknown,              // Unknown command id
        }
    }
}

// Define the UUID (Unique Universal Identifier) of the application
pub const UUID: &str = &include_str!(concat!(env!("OUT_DIR"), "/uuid.txt"));

// Include the bitcoin_transaction module
pub mod bitcoin_transaction;