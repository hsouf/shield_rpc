use serde_derive::Deserialize;
use serde::Serialize;


#[derive(Debug, Deserialize, Serialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub id: i32,
    pub method: String,
    pub params: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RpcResponse<'a>  {
   pub id: i8,
   pub   jsonrpc: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub   result: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub   error: Option<RpcError>,
}
impl<'a> RpcResponse<'a> {
    // Constructor to create a new RpcResponse with default values
    pub fn new(result: Option<&'a str>, error: Option<RpcError>) -> Self {
        RpcResponse {
            id: 2,
            jsonrpc: "2.0",
            result,
            error,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RpcError {
    pub code: i32,
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum RpcErrorCode {
   SuspiciousAddress,
   InvalidParams,
}

impl RpcErrorCode {
    pub fn to_error_code(&self) -> i32 {
        match self {
            RpcErrorCode::SuspiciousAddress => 1, 
            RpcErrorCode::InvalidParams => -32602, 
        }
    }
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
       
        Ok(Transaction { to })
    }
}

