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

/** Bitcoin Transition Input */
pub struct InputTransaction{
    prev_txid: [u8; 32],
    prev_index: u32,
    script_sig: Vec<u8>,
    sequence: u32,
}

impl InputTransaction
{
    pub fn new(prev_txid: &[u8; 32], prev_index: u32, script_sig: Vec<u8>, sequence: u32) -> InputTransaction
    {
        InputTransaction
        {
            prev_txid: *prev_txid,
            prev_index: prev_index,
            script_sig: script_sig,
            sequence: sequence,
        }
    }
}

/** Bitcoin Transition Output */
pub struct OutputTransaction{
    value: u64,
    script_pubkey: Vec<u8>,
}

impl OutputTransaction
{
    pub fn new(value: u64, script_pubkey: Vec<u8>) -> OutputTransaction
    {
        OutputTransaction
        {
            value: value,
            script_pubkey: script_pubkey,
        }
    }
}

/** Bitcoin Transation */
pub struct Transaction{
    version: u32,
    inputs: Vec<InputTransaction>,
    outputs: Vec<OutputTransaction>,
    lock_time: u32,
}

impl Transaction
{
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

    pub fn add_input(&mut self, input: InputTransaction)
    {
        self.inputs.push(input);
    }

    pub fn delele_input(&mut self, index : usize) -> Result<usize, &'static str>
    {
        if index < self.inputs.len()
        {
            self.inputs.remove(index);
            return Ok(self.inputs.len());
        }
        return Err("Index out of range");
    }

    pub fn get_inputs(&self) -> &Vec<InputTransaction>
    {
        &self.inputs
    }

    pub fn add_output(&mut self, output: OutputTransaction)
    {
        self.outputs.push(output);
    }

    pub fn delete_output(&mut self, index: usize) -> Result<usize, &'static str>
    {
        if index < self.outputs.len()
        {
            self.outputs.remove(index);
            return Ok(self.outputs.len());
        }
        return Err("Index out of range");
    }

    pub fn get_outputs(&self) -> &Vec<OutputTransaction>
    {
        &self.outputs
    }

    /** Function to serialize the Transition struct to the bitcoin transaction byte format*/ 
    pub fn serialize(&self) -> Vec<u8>
    {
        let mut serialized = Vec::new();
        serialized.extend_from_slice(&self.version.to_le_bytes());
        serialized.extend_from_slice(&var_int(self.inputs.len()));
        for input in self.inputs.iter()
        {
            serialized.extend_from_slice(&input.prev_txid);
            serialized.extend_from_slice(&input.prev_index.to_le_bytes());
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
}

/** Funtion to calculate the length in VarInt format*/
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

#[cfg(test)]
mod tests {
    use super::{InputTransaction, OutputTransaction, Transaction, var_int};

    #[test]
    fn test_var_int() {
        assert_eq!(var_int(0), vec![0]);
        assert_eq!(var_int(0xfd), vec![0xfd, 0xfd, 0x00]);
        assert_eq!(var_int(0xffff), vec![0xfe, 0xff, 0xff, 0x00, 0x00]);
        assert_eq!(var_int(0x10000), vec![0xfe, 0x00, 0x00, 0x01, 0x00]);
        assert_eq!(var_int(0xffffffff), vec![0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(var_int(0x100000000), vec![0xff, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_transaction() {
        let in_tx = InputTransaction::new(&[0x01; 32], 0, vec![0x02; 4], 0xffffffff);
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
