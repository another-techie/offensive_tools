# Disclaimer and Legal

Scanning hosts without permission may be interpreted as an attack (regardless of intent) in some jurisdictions. Do not use this script without prior written consent from the owner of the systems you are scanning. Follow all laws, regulations, and guidelines in your jurisdiction. As the user of this script you are responsible for your actions. The programer of this script isn't responsible or accountable for any actions performed with the script.


# Port Scan
This script is a basic port scanner with banner grabbing. Presently, it only support TCP scanning. UDP support may be added in the future. It was created as a side project.


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