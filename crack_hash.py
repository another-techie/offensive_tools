import hashlib
import argparse
from wordlists import chunk_wordlist
import concurrent.futures
from threading import Event
from termcolor import colored
# from sys import path

# path.append('../brute_forcing')

def determine_hash(hash_type):
    hashes = ("md5sum" ,"sha1", "sha256", "sha512")  
    if hash_type in hashes:
        return hash_type
     
    else:
        print(colored("[--] Unsupported hashing algorithm specified", 'red'))
        exit()


def main():
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("hash_type", help="Hashing algorithm", type=str)
    parser.add_argument('-s', dest='salt', help='Salt to append to hash', type=str)
    parser.add_argument('-w', dest='wordlist', help='Wordlist with passwords', type=str, default=False, required=True)
    parser.add_argument('-t', dest='threads', help='Number of concurrent connections', type=int, default=4)
    args = parser.parse_args()

    all_wordlist_chunks = chunk_wordlist(args.wordlist, args.threads)

    # Match specified hash type with hash cracking function
    hash_algorithm = determine_hash(args.hash_type)
    hash_cracking_function = 'crack_' + hash_algorithm

    finished = Event()
    exit()
    with concurrent.futures.ThreadPoolExecutor() as executor:
        for wordlist_chunk in all_wordlist_chunks:
            executor.submit(hash_cracking_function, wordlist_chunk, args.salt, finished)




if __name__ == '__main__':
	main()