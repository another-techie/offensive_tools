# Disclaimer and Legal

Use of these scripts against targets without expressly written consent from the system owner will likely be interpreted as an attack (regardless of intent or motive) in many jurisdictions. Do not use these scripts without prior written consent from the owner of the system(s) you are testing. **Follow all laws, regulations, and guidelines in your jurisdiction.** As the user of these scripts you are responsible for your actions. The programer of these tools is not responsible or accountable for any actions performed with them.


# Purpose and Structure
This repository is a collection of offensive security scripts I'm working on out of curiosity. Most of them work, but may be a little buggy. These scripts haven't been battle tested during penetration tests. My efforts here are primarily educational. My goal is to produce functional tools more so than the highest quality tools.

The tools are organized in folders by purpose. Readmes for each script are present in the respective folders. The one exception is scanning and enumeration scripts which are currently stored in the root of this repository.

# Port Scan
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