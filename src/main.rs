mod types;
mod utils;

use csv::ReaderBuilder;
use warp::Filter;
use web3::types::H160;
use std::error::Error;
use hex;
use types::{JsonRpcRequest,RpcResponse,Transaction};
use utils::option_string_to_h160;


const ALERT_LIST_URL: &str = "https://raw.githubusercontent.com/forta-network/starter-kits/1131fb4a3221c611d931c7b212fb6a4077934d6b/scam-detector-py/manual_alert_list.tsv"; // Replace with your URL

#[tokio::main]
async fn main() {
    // Call an async function from a non-async context (block until it's done)
    let alert_list=fetch_alert_list(ALERT_LIST_URL).await.unwrap();
 
    let route = warp::path!("api" )
    .and(warp::post())
    .and(warp::body::json())
    .map(  move |body: JsonRpcRequest| {
        if body.jsonrpc != "2.0" {
            return warp::reply::with_status(
                warp::reply::json(&RpcResponse {
                    id: None,
                    jsonrpc: "2.0".to_string(),
                    result: None,
                    error: Some("Invalid JSON-RPC 2.0 request.".to_string()),
                }),
                warp::http::StatusCode::BAD_REQUEST,
            );
        }

        // Ensure the method is "eth_sendRawTransaction"
        if body.method != "eth_sendRawTransaction" {
            return warp::reply::with_status(
                warp::reply::json(&RpcResponse {
                    id: None,
                    jsonrpc: "2.0".to_string(),
                    result: None,
                    error: Some("Invalid method. Expected 'eth_sendRawTransaction'.".to_string()),
                }),
                warp::http::StatusCode::BAD_REQUEST,
            );
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



fn handle_rpc_request(tx: Transaction, alert_list: &[H160]) -> warp::reply::WithStatus<warp::reply::Json> {

    let to_address = option_string_to_h160(tx.to).unwrap();

 // Check if the to address is in the alert list
 let error_message = if !alert_list.contains(&to_address) {
    Some(format!("Interaction with suspicious contract. To Address: {:?}", to_address))
} else {
    None
};

let status_code = match error_message {
    Some(_) => warp::http::StatusCode::BAD_REQUEST,
    None => warp::http::StatusCode::OK,
};

// Create the RPC response
let response = RpcResponse {
    id: None, // Set the appropriate ID if needed
    jsonrpc: "2.0".to_string(),
    result: if error_message.is_none() { Some("Transaction decoded successfully.".to_string()) } else { None },
    error: error_message,
};


let json_response = warp::reply::json(&response);


warp::reply::with_status(json_response, status_code)
   
    
}




