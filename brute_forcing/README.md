# Brute Forcing Scripts
## SSH
```
usage: ssh_brute.py [-h] [-p SSH_PORT] -u USERNAME -w WORDLIST [-t THREADS] [-a] target_host

positional arguments:
  target_host  Specify target host

options:
  -h, --help   show this help message and exit
  -p SSH_PORT  SSH server port
  -u USERNAME  Username
  -w WORDLIST  Wordlist with passwords
  -t THREADS   Number of concurrent connections
  -a           Show all attempted logins
```

## FTP
```
usage: ftp_brute.py [-h] [-p FTP_PORT] -u USERNAME -w WORDLIST [-t THREADS] [-a] target_host

positional arguments:
  target_host  Specify target host

options:
  -h, --help   show this help message and exit
  -p FTP_PORT  FTP server port
  -u USERNAME  Username
  -w WORDLIST  Wordlist with passwords
  -t THREADS   Wordlist with passwords
  -a           Show all attempted logins
```