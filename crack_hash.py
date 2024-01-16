import hashlib
from binascii import hexlify
import argparse
import concurrent.futures
from Crypto.Hash import MD4
from threading import Event
from termcolor import colored


from wordlists import chunk_wordlist



def ntlm(hash_input):
    hash = MD4.new(hash_input.encode('utf-16le')).digest()
    hash = hexlify(hash)
    return hash.decode()

def md5(hash_input):
    hash_input = bytes(hash_input)
    hash = hashlib.md5(hash_input)
    return hash.hexdigest()

def sha1(hash_input):
    hash_input = bytes(hash_input)
    hash = hashlib.sha1(hash_input)
    return hash.hexdigest()

def sha224(hash_input):
    hash_input = bytes(hash_input)
    hash = hashlib.sha224(hash_input)
    return hash.hexdigest()

def sha256(hash_input):
    hash_input = bytes(hash_input)
    hash = hashlib.sha256(hash_input)
    return hash.hexdigest()

def sha384(hash_input):
    hash_input = bytes(hash_input)
    hash = hashlib.sha384(hash_input)
    return hash.hexdigest()

def sha512(hash_input):
    hash_input = bytes(hash_input)
    hash = hashlib.sha512(hash_input)
    return hash.hexdigest()

def sha3_224(hash_input):
    hash_input = bytes(hash_input)
    hash = hashlib.sha3_224(hash_input)
    return hash.hexdigest()

def sha3_256(hash_input):
    hash_input = bytes(hash_input)
    hash = hashlib.sha3_256(hash_input)
    return hash.hexdigest()

def sha3_384(hash_input):
    hash_input = bytes(hash_input)
    hash = hashlib.sha3_384(hash_input)
    return hash.hexdigest()

def sha3_512(hash_input):
    hash_input = bytes(hash_input)
    hash = hashlib.sha3_512(hash_input)
    return hash.hexdigest()


def determine_hash(hash_mode):
    hashes = {1:ntlm, 2:md5, 3:sha1, 4:sha224, 5:sha256, 6:sha384, 7:sha512, 8:sha3_224, 9:sha3_256,
              10:sha3_224, 11:sha3_512}
    
    if hash_mode in hashes.keys():
        return hashes[hash_mode]
     
    else:
        print(colored("[--] Unknown hash mode specified", 'red'))
        exit()


def crack_hash(algorithm, input_hash, wordlist_chunk, event, salt=False):
    
    # Iterate through assigned chunk of wordlist
    for word in wordlist_chunk:

        # Check if event is set. Event is set when match is found.
        if not event.is_set():
            word = word[0].strip()
            word_string = word

            # Encode word using default text encoding
            word = word.encode()

            generated_hash = algorithm(word)
            
            # If hashes match
            if generated_hash == input_hash:
                print(colored("[+] INPUT HASH: {}".format(input_hash), 'blue'))
                print(colored("[+] GENERATED HASH: {}".format(generated_hash), 'blue'))
                print(colored("[+] HASH CRACKED: {}".format(word_string), 'light_green'))
                event.set()


def main():
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("-m", help="Hash mode", dest="hash_mode", type=int, required=True)
    parser.add_argument('-s', dest='salt', help='Salt to append to hash', type=str)
    parser.add_argument('-w', dest='wordlist', help='Wordlist with passwords', type=str, default=False, required=True)
    parser.add_argument('-t', dest='threads', help='Number of concurrent connections', type=int, default=4)
    parser.add_argument('hash', help='Hash to crack', type=str)
    args = parser.parse_args()

    # Match specified hash mode with hash algorithm
    hash_algorithm = determine_hash(args.hash_mode)

    all_wordlist_chunks = chunk_wordlist(args.wordlist, args.threads)
    finished = Event()
    with concurrent.futures.ThreadPoolExecutor() as executor:
        for wordlist_chunk in all_wordlist_chunks:
            executor.submit(crack_hash, hash_algorithm, args.hash, wordlist_chunk, finished, args.salt)



if __name__ == '__main__':
	main()