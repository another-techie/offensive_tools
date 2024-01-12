# Disclaimer and Legal

Use of these scripts against targets without expressly written consent from the system owner will likely be interpreted as an attack (regardless of intent or motive) in many jurisdictions. Do not use these scripts without prior written consent from the owner of the system(s) you are testing. **Follow all laws, regulations, and guidelines in your jurisdiction.** As the user of these scripts you are responsible for your actions. The programer of these tools is not responsible or accountable for any actions performed with them.


# Purpose and Structure
This repository is a collection of offensive security scripts I'm working on out of curiosity. Most of them work, but may be a little buggy. These scripts haven't been battle tested during penetration tests. My efforts here are primarily educational. My goal is to produce functional tools more so than the highest quality tools.


## Port Scan
This script is a basic port scanner with banner grabbing. Presently, it only support TCP scanning. UDP support may be added in the future.

```
usage: portscan.py [-h] [-p TARGET_PORTS] [-b] [-c] target_host

positional arguments:
  target_host      Specify target host

options:
  -h, --help       show this help message and exit
  -p TARGET_PORTS  Specify target port, ports seperated by commas, or port
                   range (ex. 20-23). If a port isn't specified, this script
                   will scan ports 1-1023 by default.
  -b               Enable banner grabbing from open ports. Banner grabbing is
                   disabled by default.
  -c               Show closed ports. Display of closed ports is disabled by
                   default
```

## Brute Forcer
This script is a brute forcer for network protocols. The number of concurrent threads can be specified, but a default value is available on a per protocol basis. This is to prevent accidental an DOS attack against the target server. Presently the supported protocols are:
* SSH
* FTP
```
usage: brute_force.py [-h] [-p SERVICE_PORT] -u USERNAME -w WORDLIST [-t THREADS] [-a] target_host

positional arguments:
  target_host      Specify target host in the format protocol://host

options:
  -h, --help       show this help message and exit
  -p SERVICE_PORT  Target port
  -u USERNAME      Username
  -w WORDLIST      Wordlist with passwords
  -t THREADS       Number of concurrent connections
  -a               Show all attempted logins
```