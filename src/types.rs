use serde_derive::Deserialize;
use serde::Serialize;


#[derive(Debug, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub id: i32,
    pub method: String,
    pub params: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RpcResponse {
   pub  id: Option<u64>,
   pub jsonrpc: String,
   pub result: Option<String>,
   pub  error: Option<String>,
}


pub struct Transaction { 
   pub to: Option<String>,  // To address
}


impl Transaction {
   pub fn new(raw_tx: &str) -> Result<Self, String> {
        // Assuming a basic format where fields are in fixed positions
        if raw_tx.len() < 32 * 2 {
            return Err("Invalid raw transaction length".to_string());
        }

        let to = if &raw_tx[50..90] == "0000000000000000000000000000000000000000" {
            None
        } else {
            Some(raw_tx[50..90].to_owned())
        };
       
        Ok(Transaction {  to })
    }
}

