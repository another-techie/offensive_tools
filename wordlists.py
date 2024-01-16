from termcolor import colored
from math import ceil

def chunk_wordlist(wordlist, number_of_threads):
    try:
        file = open(wordlist, 'r')
        passwords = file.readlines()
             
        number_of_passwords = len(passwords)
        print(colored("Total passwords: {}".format(number_of_passwords), 'blue'))

        passwords_per_list = number_of_passwords / number_of_threads
        passwords_per_list = ceil(passwords_per_list)

        print(colored("Threads: {}".format(number_of_threads), 'blue'))

        print(colored("Assigning ~ {} passwords per thread".format(passwords_per_list), 'blue'))
        print("\n")
        
        all_wordlist_chunks = []
        wordlist_chunk = []
        index = 0
        counter = passwords_per_list
        index_increment = number_of_threads
        total_passwords = 0
        round = 0
        while number_of_threads != 0:
            while counter != 0:         
                try:
                    wordlist_chunk.append(passwords[index].split())
                    index += index_increment
                    counter -= 1
                except IndexError:
                        break

            round += 1
            
            counter = passwords_per_list
            index = round
            number_of_threads -= 1
            all_wordlist_chunks.append(wordlist_chunk)
            total_passwords += len(wordlist_chunk)
            wordlist_chunk = []
        
        
     
        file.close()

        return all_wordlist_chunks
    except FileNotFoundError:
         print(colored("[--] The specified wordlist does not exist", 'red'))

    except PermissionError:
         print(colored("[--] Insufficient permissions to open the wordlist", 'red'))

    