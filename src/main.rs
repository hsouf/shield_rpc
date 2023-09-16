use csv::ReaderBuilder;

use warp::Filter;
use web3::types::{H160};
use std::error::Error;
use hex;
use serde_derive::Deserialize;




const ALERT_LIST_URL: &str = "https://raw.githubusercontent.com/forta-network/starter-kits/1131fb4a3221c611d931c7b212fb6a4077934d6b/scam-detector-py/manual_alert_list.tsv"; // Replace with your URL


#[derive(Debug, Deserialize)]
struct Params {
    #[serde(rename = "0")]
    pub raw_transaction: String,
}

#[derive(Debug, Deserialize)]
struct JsonRpcRequest {
    pub jsonrpc: String,
    pub id: i32,
    pub method: String,
    pub params: Vec<String>,
}
#[tokio::main]
async fn main() {
    // Call an async function from a non-async context (block until it's done)
    let alert_list=fetch_alert_list(ALERT_LIST_URL).await.unwrap();
 
    let route = warp::path!("api" )
    .and(warp::post())
    .and(warp::body::json())
    .map(  move |body: JsonRpcRequest| {
        if body.jsonrpc != "2.0" {
            return warp::reply::with_status("Invalid JSON-RPC 2.0 request.".to_string(), warp::http::StatusCode::BAD_REQUEST);
        }
    
        // Ensure the method is "decode_tx"
        if body.method != "eth_sendRawTransaction" {
            return warp::reply::with_status("Invalid method. Expected 'eth_sendRawTransaction'.".to_string(), warp::http::StatusCode::BAD_REQUEST);
        }
    let x=body.params.get(0).unwrap();
       
   let t=Transaction::new(&x).unwrap();

        handle_rpc_request(t, &alert_list)
    });
    warp::serve(route).run(([127, 0, 0, 1], 3030)).await;

}

 async fn fetch_alert_list(url: &str) -> Result<Vec<H160>, Box<dyn Error>> {
    let response = reqwest::get(url).await?.bytes().await?;
    let text = String::from_utf8(response.to_vec())?;
    
    let mut alert_list = Vec::new();
    let mut rdr = ReaderBuilder::new().delimiter(b'\t').has_headers(true).from_reader(text.as_bytes());

    let entity_index = match rdr.headers()?.iter().position(|h| h == "Entity") {
        Some(index) => index,
        None => {
            return Err("Column 'Entity' not found".into());
        }
    };
   
    for result in rdr.records() {
        let record = result?;
        if let Some(address) = record.get(entity_index) {
            // Trim any leading or trailing whitespace
            let trimmed_address = address.trim();
    
            if trimmed_address.is_empty() {
                // Skip empty addresses
                continue;
            }
    
            // Ensure the address starts with "0x"
            if !trimmed_address.starts_with("0x") {
                // Handle the error: Address doesn't start with "0x"
                eprintln!("Error: Address doesn't start with '0x': {}", trimmed_address);
                continue;
            }
    
            if let Ok(bytes) = hex::decode(&trimmed_address[2..]) {
                let h160 = H160::from_slice(&bytes);
                alert_list.push(h160);
            } else {
                // Handle the error: Invalid hexadecimal format
                eprintln!("Error: Invalid hexadecimal format for address: {}", trimmed_address);
            }
        }
    }
    
    Ok(alert_list)
} 



fn handle_rpc_request(tx: Transaction, alert_list: &[H160]) -> warp::reply::WithStatus<String>{

    let to_address = option_string_to_h160(tx.to).unwrap();

    if !alert_list.contains(&to_address) {
     warp::reply::with_status(
        format!("Error: Interaction with suspicious contract. To Address: {:?}", to_address),
            warp::http::StatusCode::BAD_REQUEST,
        )
    } else {
      warp::reply::with_status(
            "Transaction decoded successfully.".to_string(),
            warp::http::StatusCode::OK,
        )
    }
}
fn option_string_to_h160(opt_string: Option<String>) -> Option<H160> {
    opt_string.map(|s| {
        // Parse the string as H160
        H160::from_slice(&hex::decode(&s).unwrap_or_default())
    })
}

struct Transaction { 
    to: Option<String>,  // To address
}

impl Transaction {
    fn new(raw_tx: &str) -> Result<Self, String> {
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