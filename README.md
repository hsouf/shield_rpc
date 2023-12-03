## SHIELD RPC
A simple proxy on top of your RPC node to block any interaction with fraudulent contracts/wallets before they are forwarded to your original RPC.

### How does it work?

It's easy! Just add your preferred RPC URL as a query parameter, kickstart your server, and you're good to go. Any transactions that is sending or calling a flagged suspicious address will be immediately blocked. Right now for the POC I'm using the alert list genereously put together [here](https://github.com/forta-network/starter-kits/blob/1131fb4a3221c611d931c7b212fb6a4077934d6b/scam-detector-py/manual_alert_list.tsv#L177) by Certik, AegisWeb3, Peckshield, Blocksec...

Example:
```
http://localhost:3030/shield?rpc=https://rpc-goerli.flashbots.net/hint=hash
``````
![shield_rpc drawio](https://github.com/hsouf/shield_rpc/assets/37840702/42867beb-e82f-42c1-a6b4-e93a3a2b30f0)

### Running locally

Build the Rust Project:
``````
Cargo build
``````

Run project 
`````
cargo run
`````

## Upcoming

- [ ] Address poisoning scams protection (block any interaction with a vanity address that looks like yours)
- [ ] Add a wait time for txs before they get forwarded in case you changed your mind at the last minute (just like emails but better)
- [ ] Real-time update of the alert list

