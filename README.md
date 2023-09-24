## SHIELD RPC
A simple proxy that blocks any transactions with suspicious interactions with fraudulent tokens/contracts/addresses before they are forwarded to your original RPC.

How does it work?

It's easy! Just add your preferred RPC URL as a query parameter, kickstart your server, and you're good to go. Any transactions that is sending or calling a flagged address will be immediately blocked. 

```
http://localhost:3030/shield?rpc=https://rpc-goerli.flashbots.net/
``````

## Upcoming

- Address poisoning scams protection (block any interaction with a vanity address that looks like yours)
- Add a wait time for txs before they get forwarded in case you changed your mind at the last minute (just like emails but better)
- Real-time update of the alert_list

