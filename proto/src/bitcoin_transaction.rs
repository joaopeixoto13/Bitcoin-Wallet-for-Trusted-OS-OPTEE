/**
 * @brief Transaction structure
 * @note If the endianess is not specified, it is assumed to be Little Endian.
 * 
 * version (4 bytes)        
 * in_len (1-9 bytes)
 * 
 * prv_txid (32 bytes)
 * prv_index (4 bytes)
 * script_len (1-9 bytes)
 * script_sig (Variable) ==> Big endian
 * sequence (4 bytes)
 * 
 * out_len (1-9 bytes)
 * value (8 bytes)
 * script_len (1-9 bytes)
 * script_pubkey (Variable) ==> Big endian
 * 
 * locktime (4 bytes)
 * 
 * @note (VarInt (1-9 bytes))
 * @note If scr_len <= 0xFC, then scr_len is {BYTE}
 * @note If scr_len <= 0xFFFF, then scr_len is {0xFD, BYTE, BYTE}
 * @note If scr_len <= 0xFFFFFFFF, then scr_len is {0xFE, BYTE, BYTE, BYTE, BYTE}
 * @note If scr_len <= 0xFFFFFFFFFFFFFFFF, then scr_len is {0xFF, BYTE, BYTE, BYTE, BYTE, BYTE, BYTE, BYTE, BYTE}
 * @note [All the fields are in Little Endian]
 */

/**
 * @brief Bitcoin Transition Previous Output to spent
*/
#[derive(Debug)]
pub struct BaseOutputTransaction{
    pub txid: [u8; 32],
    pub index: u32,
}

/**
 * @brief Bitcoin Transition Input
*/
#[derive(Debug)]
pub struct InputTransaction{
    pub base_output: BaseOutputTransaction,
    pub script_sig: Vec<u8>,
    pub sequence: u32,
}

/**
 * @brief Bitcoin Transition Input implementation
*/
impl InputTransaction
{
    // Constructor
    pub fn new(base_output: BaseOutputTransaction, script_sig: Vec<u8>, sequence: u32) -> InputTransaction
    {
        InputTransaction
        {
            base_output:base_output,
            script_sig: script_sig,
            sequence: sequence,
        }
    }
}

/**
 * @brief Bitcoin Transition Output
*/
#[derive(Debug)]
pub struct OutputTransaction{
    pub value: u64,
    pub script_pubkey: Vec<u8>,
}

/**
 * @brief Bitcoin Transition Output implementation
*/
impl OutputTransaction
{
    // Constructor
    pub fn new(value: u64, script_pubkey: Vec<u8>) -> OutputTransaction
    {
        OutputTransaction
        {
            value: value,
            script_pubkey: script_pubkey,
        }
    }
}

/**
 * @brief Bitcoin Transition
 * @details This structure is used to represent a Bitcoin Transition, composed by the inputs, outputs and some other fields
*/
#[derive(Debug)]
pub struct Transaction{
    pub version: u32,
    pub inputs: Vec<InputTransaction>,
    pub outputs: Vec<OutputTransaction>,
    pub lock_time: u32,
}

/**
 * @brief Bitcoin Transition implementation
*/
impl Transaction
{
    // Constructor
    pub fn new(version: u32, inputs: Vec<InputTransaction>, outputs: Vec<OutputTransaction>, lock_time: u32) -> Transaction
    {
        Transaction
        {
            version: version,
            inputs: inputs,
            outputs: outputs,
            lock_time: lock_time,
        }
    }

    // Add an input to the transaction
    pub fn add_input(&mut self, input: InputTransaction)
    {
        self.inputs.push(input);
    }

    // Delete an input from the transaction
    pub fn delele_input(&mut self, index : usize) -> Result<usize, &'static str>
    {
        if index < self.inputs.len()
        {
            self.inputs.remove(index);
            return Ok(self.inputs.len());
        }
        return Err("Index out of range");
    }

    // Get the inputs of the transaction
    pub fn get_inputs(&self) -> &Vec<InputTransaction>
    {
        &self.inputs
    }

    // Add an output to the transaction
    pub fn add_output(&mut self, output: OutputTransaction)
    {
        self.outputs.push(output);
    }

    // Delete an output from the transaction
    pub fn delete_output(&mut self, index: usize) -> Result<usize, &'static str>
    {
        if index < self.outputs.len()
        {
            self.outputs.remove(index);
            return Ok(self.outputs.len());
        }
        return Err("Index out of range");
    }

    // Get the outputs of the transaction
    pub fn get_outputs(&self) -> &Vec<OutputTransaction> 
    {
        &self.outputs
    }

    // Get the number of inputs and outputs of the transaction
    pub fn get_lengths(&self) -> (usize, usize)
    {
        (self.inputs.len(), self.outputs.len())
    }

    // Function to serialize the Transition struct to the bitcoin transaction byte format 
    pub fn serialize(&self) -> Vec<u8>
    {
        let mut serialized = Vec::new();
        serialized.extend_from_slice(&self.version.to_le_bytes());
        serialized.extend_from_slice(&var_int(self.inputs.len()));
        for input in self.inputs.iter()
        {
            let aux: &Vec<u8> = &input.base_output.txid.to_vec().into_iter().rev().collect();
            serialized.extend(aux);
            serialized.extend_from_slice(&input.base_output.index.to_le_bytes());
            serialized.extend_from_slice(&var_int(input.script_sig.len() as usize));
            serialized.extend_from_slice(&input.script_sig);
            serialized.extend_from_slice(&input.sequence.to_le_bytes());
        }
        serialized.extend_from_slice(&var_int(self.outputs.len()));
        for output in self.outputs.iter()
        {
            serialized.extend_from_slice(&output.value.to_le_bytes());
            serialized.extend_from_slice(&var_int(output.script_pubkey.len() as usize));
            serialized.extend_from_slice(&output.script_pubkey);
        }
        serialized.extend_from_slice(&self.lock_time.to_le_bytes());
        serialized
    }

    // Function to deserialize the bitcoin transaction byte format to the Transition struct
    pub fn deserialize(serialized: &[u8]) -> Transaction
    {
        let mut index: usize = 0;
        let version = u32::from_le_bytes([serialized[index], serialized[index+1], serialized[index+2], serialized[index+3]]);
        index += 4;
        let inputs_len = var_int_len(&serialized[index..]);
        index += inputs_len.1;
        let mut inputs = Vec::new();
        for _ in 0..inputs_len.0
        {
            let mut txid = [0u8; 32];
            txid.copy_from_slice(&serialized[index..index+32]);
            index += 32;
            let index_t = u32::from_le_bytes([serialized[index], serialized[index+1], serialized[index+2], serialized[index+3]]);
            index += 4;
            let script_len = var_int_len(&serialized[(index as usize)..]);
            index +=  script_len.1;
            let script_sig = serialized[index..index+script_len.0].to_vec();
            index += script_len.0;
            let sequence = u32::from_le_bytes([serialized[index as usize], serialized[(index+1) as usize], serialized[(index+2) as usize], serialized[(index+3) as usize]]);
            index += 4;
            let base_output = BaseOutputTransaction{txid: txid, index: index_t};
            let input = InputTransaction::new(base_output, script_sig, sequence);
            inputs.push(input);
        }
        let outputs_len = var_int_len(&serialized[index..]);
        index += outputs_len.1;
        let mut outputs = Vec::new();
        for _ in 0..outputs_len.0
        {
            let value = u64::from_le_bytes([serialized[index], serialized[index+1], serialized[index+2], serialized[index+3], serialized[index+4], serialized[index+5], serialized[index+6], serialized[index+7]]);
            index += 8;
            let script_len = var_int_len(&serialized[index..]);
            index += script_len.1;
            let script_pubkey = serialized[index..index+script_len.0].to_vec();
            index += script_len.0;
            let output = OutputTransaction::new(value, script_pubkey);
            outputs.push(output);
        }
        let lock_time = u32::from_le_bytes([serialized[index], serialized[index+1], serialized[index+2], serialized[index+3]]);
        Transaction::new(version, inputs, outputs, lock_time)
    }
}

/**
 * @brief Funtion to calculate the length in VarInt format
 * @note The VarInt format is used to represent the length of a vector in the bitcoin transaction byte format, because 
 * this approach allows different lengths to be represented in a variable number of bytes (generic approach)
*/
pub fn var_int(length: usize) -> Vec<u8>
{
    let mut var_int = Vec::new();
    if length < 0xfd
    {
        var_int.push(length as u8);
    }
    else if length < 0xffff
    {
        var_int.push(0xfd);
        var_int.extend_from_slice(&length.to_le_bytes()[0..2]);
    }
    else if length < 0xffffffff
    {
        var_int.push(0xfe);
        var_int.extend_from_slice(&length.to_le_bytes()[0..4]);
    }
    else
    {
        var_int.push(0xff);
        var_int.extend_from_slice(&length.to_le_bytes());
    }
    return var_int;
}

// Funtion to calculate the length in VarInt format
pub fn var_int_len(serialized: &[u8]) -> (usize, usize)
{
    let mut length: usize = 0;
    let mut index: usize = length;
    if serialized[index] < 0xfd
    {
        length = serialized[index] as usize;
        index += 1;
    }
    else if serialized[index] == 0xfd
    {
        length = u16::from_le_bytes([serialized[index+1], serialized[index+2]]) as usize;
        index += 3;
    }
    else if serialized[index] == 0xfe
    {
        length = u32::from_le_bytes([serialized[index+1], serialized[index+2], serialized[index+3], serialized[index+4]]) as usize;
        index += 5;
    }
    else
    {
        length = u64::from_le_bytes([serialized[index+1], serialized[index+2], serialized[index+3], serialized[index+4], serialized[index+5], serialized[index+6], serialized[index+7], serialized[index+8]]) as usize;
        index += 9;
    }
    return (length, index);
}


/**
 * @brief Test module
 * @note This module contains the tests for the functions of the transaction module
*/
#[cfg(test)]
mod tests {

    // Import the functions to be tested
    use super::{InputTransaction, OutputTransaction, BaseOutputTransaction, Transaction, var_int};

    // Test the function to calculate the length in VarInt format
    #[test]
    fn test_var_int() {
        assert_eq!(var_int(0), vec![0]);
        assert_eq!(var_int(0xfd), vec![0xfd, 0xfd, 0x00]);
        assert_eq!(var_int(0xffff), vec![0xfe, 0xff, 0xff, 0x00, 0x00]);
        assert_eq!(var_int(0x10000), vec![0xfe, 0x00, 0x00, 0x01, 0x00]);
        assert_eq!(var_int(0xffffffff), vec![0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(var_int(0x100000000), vec![0xff, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]);
    }

    // Test the transaction serialization
    #[test]
    fn test_transaction() {
        let in_tx = InputTransaction::new(BaseOutputTransaction { txid: ([0x01;32]), index: (0) }, vec![0x02; 4], 0xffffffff);
        let out_tx = OutputTransaction::new(0x0102, vec![0x02; 4]);
        let tx = Transaction::new(1, vec![in_tx], vec![out_tx], 0);
        assert_eq!(tx.serialize(), 
        vec![0x01, 0x00, 0x00, 0x00, 
        0x01, 
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x00, 0x00, 0x00, 0x00,
        0x04,
        0x02, 0x02, 0x02, 0x02,
        0xff, 0xff, 0xff, 0xff,
        0x01,
        0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x04,
        0x02, 0x02, 0x02, 0x02,
        0x00, 0x00, 0x00, 0x00]);
    }
}