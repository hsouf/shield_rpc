mod types;
mod utils;

use csv::ReaderBuilder;
use warp::Filter;
use web3::types::H160;
use std::error::Error;
use hex;
use types::{JsonRpcRequest,RpcResponse,Transaction,RpcError};
use utils::option_string_to_h160;
use reqwest::{Client, StatusCode};
use serde_json::Value;


const ALERT_LIST_URL: &str = "https://raw.githubusercontent.com/forta-network/starter-kits/1131fb4a3221c611d931c7b212fb6a4077934d6b/scam-detector-py/manual_alert_list.tsv"; // Replace with your URL

#[tokio::main]
async fn main() {

    //let mutalert_list=fetch_alert_list(ALERT_LIST_URL).await.unwrap();// TODO: add support for real time update of the alert list

    let route = warp::path!("shield")
    .and(warp::post())
    .and(warp::body::json())
    .then(|request: JsonRpcRequest| async move {
        let target="https://rpc-goerli.flashbots.net/?hint=hash";
        let empty_slice: &[H160] = &[];
        if request.method=="eth_sendRawTransaction"{
           handle_eth_send_raw_transaction(&request, &empty_slice, target).await
        }else{
          handle_rpc_request(&request, target).await
           
    }
      
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



fn is_malicious_to_address(req: &JsonRpcRequest, alert_list: &[H160]) -> bool {
let x=req.params.get(0).unwrap(); 
let tx=Transaction::new(&x).unwrap();
let to_address = option_string_to_h160(tx.to).unwrap();
 // Check if the to address is in the alert list
if alert_list.contains(&to_address) {
   return true
} else {
   return false
};
}



async fn handle_eth_send_raw_transaction(req: &JsonRpcRequest, alert_list: &[H160], target_endpoint: &str) -> warp::reply::WithStatus<warp::reply::Json>  {
    
    let empty_slice: &[H160] = &[];
            let x=req.params.get(0).unwrap(); 
            let tx=Transaction::new(&x).unwrap();
            
            let to_address = option_string_to_h160(tx.to).unwrap();
           
             // Check if the to address is in the alert list
            let is_malicious_address = is_malicious_to_address(req, alert_list);
         
            let  error_message: Option<String> = if !is_malicious_address {
                Some(format!("Interaction with a suspicious contract. To Address: {:?}", to_address))
            } else {
                None
            };
  
         
            if is_malicious_address {

               
                let response = RpcResponse::new(None,error_message.map(|message| RpcError {
                    code: 0,
                    message,
                })); 
                
                let json_response = warp::reply::json(&response);
            
                warp::reply::with_status(json_response, warp::http::StatusCode::OK)
            }else{

                let response = forward_request_to_target_rpc(&req, &target_endpoint).await; 
                let  json_response;
                match response {
                  Ok(res) => {
                      json_response = warp::reply::json(&res);            
                  }
                  Err(err) => {
                      // Create a JSON response with the error message
                      json_response = warp::reply::json(&format!("Error: {}", err));
                      // Return the JSON response with status code ACCEPTED
                       
                  }        
                  }
          
                 warp::reply::with_status(json_response, warp::http::StatusCode::OK)}

}


async fn handle_rpc_request(req: &JsonRpcRequest, target_endpoint: &str) -> warp::reply::WithStatus<warp::reply::Json>{
    let response= forward_request_to_target_rpc(req, target_endpoint).await;
    let  json_response;
    match response {
      Ok(res) => {
          json_response = warp::reply::json(&res);

          
      }
      Err(err) => {
          // Create a JSON response with the error message
          json_response = warp::reply::json(&format!("Error: {}", err));


           
      }        
      }

     warp::reply::with_status(json_response, warp::http::StatusCode::OK)
}

async fn forward_request_to_target_rpc(req: &JsonRpcRequest, target_endpoint: &str) -> Result<Value, Box<dyn Error>> {
    let client = Client::new();
    let request_json = serde_json::to_value(&req).expect("Failed to serialize JSON request"); 
    let response = client
        .post(target_endpoint)
        .json(&request_json)
        .send().await ;

        match response {
            Ok(res) => {
                if res.status().is_success() {
                    let json_response: Value = res.json().await.map_err(|err| {
                        println!("Failed to parse JSON response: {:?}", err);
                        err
                    })?;
                    Ok(json_response)
                } else {
                    Err("RPC request failed".into()) // Change this to an appropriate error type
                }
            }
            Err(err) => {
                Err(err.into())
            }
        }
        
}
