# LINFO2347 – Project Network Attacks

## Authors
Deroeux Elric (noma:)
Lévêque Quentin (noma:)

## Basic enterprise network protection
For the basic entreprise network protection we tried to keep our NFT super simplified.

- No statement have been made for routers behavior, we allow them to send/receive ping/connection.
- Routers forward behavior is "default drop" as it is a good practice

### r1 NFTable:
```
#!/usr/sbin/nft -f

flush ruleset

table inet filter { 
    chain input {
        type filter hook input priority 0; policy accept;
    }
    chain forward {
        type filter hook forward priority 0; policy drop;
        
        ct state established,related accept
        
        iif r1-eth0 oif r1-eth12 accept
    }
    chain output {
        type filter hook output priority 0; policy accept;
    }
}
```
- r1 could be ip-oriented "iif r1-eth0 ip saddr 10.1.0.0/24 accept" or shorter "iif r1-eth0 accept".
- r1 accept response to new/old connections
- DMZ servers can ping each other has the case has been discuted in teams. Otherwise additionnal firewall would have been needed for each DMZ server.

### r2 NFTable: 
```
#!/usr/sbin/nft -f 

flush ruleset

table inet filter { 
    chain input {
        type filter hook input priority 0; policy accept;
    }
    chain forward {
        type filter hook forward priority 0; policy drop;
        
        ct state established,related accept	
        
        iif r2-eth12 oif r2-eth0 ip saddr 10.1.0.0/24 accept
        
        iif r2-eth0 oif r2-eth12 accept
    }
    chain input {
        type filter hook output priority 0; policy accept;
    }
}
```
- r2 need to allow packets from workstations IPs only.
- Everything from internet can come in because of r1 drop policy that will block packet not destinated to DMZ.
### Application of rules:
We modified the topo.py to apply our basic NFTables to r1 and r2.
```python
...
def apply_nftables_rules(net: Mininet) -> None:
    info("Applying nftables rules on r1...\n")
    info(net['r1'].cmd("nft -f ~/LINFO2347/r1.nft"))
    
    info("Applying nftables rules on r2...\n")
    info(net['r2'].cmd("nft -f ~/LINFO2347/r2.nft"))
...
```
We call this function after the "add_routes" function.
