from fastecdsa import keys, curve
import platform
import multiprocessing
import hashlib
import os
import sys
import time

DATABASE = r'database/11_13_2022/'

def generate_private_key():
    return binascii.hexlify(os.urandom(32)).decode('utf-8').upper()

def private_key_to_public_key(private_key, fastecdsa):
    if fastecdsa:
        key = keys.get_public_key(int(private_key, 16), curve.secp256k1)
        return '04' + (hex(key.x)[2:].zfill(64) + hex(key.y)[2:].zfill(64))
    else:
        pk = keys.get_public_key(int(private_key, 16), curve.secp256k1)
        return '04' + (hex(pk.x)[2:].zfill(64) + hex(pk.y)[2:].zfill(64))

def public_key_to_address(public_key):
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    var = hashlib.new('ripemd160')
    encoding = bytes.fromhex(public_key)
    var.update(hashlib.sha256(encoding).digest())
    var_encoded = b'00' + var.digest()
    checksum = hashlib.sha256(hashlib.sha256(var_encoded).digest()).digest()
    var_hex = var_encoded + checksum[:4]
    n = int.from_bytes(var_hex, 'big')
    output = ''
    while n > 0:
        n, remainder = divmod(n, 58)
        output = alphabet[remainder] + output
    return output

def private_key_to_wif(private_key):
    extended_key = bytes.fromhex('80' + private_key)
    checksum = hashlib.sha256(hashlib.sha256(extended_key).digest()).digest()[:4]
    var = extended_key + checksum
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    value = int.from_bytes(var, 'big')
    result = ''
    while value > 0:
        value, mod = divmod(value, 58)
        result = alphabet[mod] + result
    return '1' * (len(private_key) - len(private_key.lstrip('0'))) + result

def main(database, args):
    while True:
        private_key = generate_private_key()
        public_key = private_key_to_public_key(private_key, args['fastecdsa']) 
        address = public_key_to_address(public_key)

        if args['verbose']:
            print(address)
        
        if address[-args['substring']:] in database:
            for filename in os.listdir(DATABASE):
                with open(DATABASE + filename) as file:
                    if address in file.read():
                        with open('plutus.txt', 'a') as plutus:
                            plutus.write('hex private key: ' + str(private_key) + '\n' +
                                         'WIF private key: ' + str(private_key_to_wif(private_key)) + '\n'
                                         'public key: ' + str(public_key) + '\n' +
                                         'uncompressed address: ' + str(address) + '\n\n')
                        break

def print_help():
    print('''Plutus homepage: https://github.com/Isaacdelly/Plutus
Plutus QA support: https://github.com/Isaacdelly/Plutus/issues


Speed test: 
execute 'python3 plutus.py time', the output will be the time it takes to bruteforce a single address in seconds


Quick start: run command 'python3 plutus.py'

By default this program runs with parameters:
python3 plutus.py verbose=0 substring=8

verbose: must be 0 or 1. If 1, then every bitcoin address that gets bruteforced will be printed to the terminal. This has the potential to slow the program down. An input of 0 will not print anything to the terminal and the bruteforcing will work silently. By default verbose is 0.

substring: to make the program memory efficient, the entire bitcoin address is not loaded from the database. Only the last <substring> characters are loaded. This significantly reduces the amount of RAM required to run the program. if you still get memory errors then try making this number smaller, by default it is set to 8. This opens us up to getting false positives (empty addresses mistaken as funded) with a probability of 1/(16^<substring>), however it does NOT leave us vulnerable to false negatives (funded addresses being mistaken as empty) so this is an acceptable compromise.

cpu_count: number of cores to run concurrently. More cores = more resource usage but faster bruteforcing. Omit this parameter to run with the maximum number of cores''')
    sys.exit(0)

def timer(args):
    start = time.time()
    private_key = generate_private_key()
    public_key = private_key_to_public_key(private_key, args['fastecdsa'])
    address = public_key_to_address(public_key)
    end = time.time()
    print(str(end - start))
    sys.exit(0)

if __name__ == '__main__':
    args = {
        'verbose': 0,
        'substring': 8,
        'fastecdsa': platform.system() in ['Linux', 'Darwin'],
        'cpu_count': multiprocessing.cpu_count(),
    }
    
    for arg in sys.argv[1:]:
        command = arg.split('=')[0]
        if command == 'help':
            print_help()
        elif command == 'time':
            timer(args)
        elif command == 'cpu_count':
            cpu_count = int(arg.split('=')[1])
            if cpu_count > 0 and cpu_count <= multiprocessing.cpu_count():
                args['cpu_count'] = cpu_count
            else:
                print('invalid input. cpu_count must be greater than 0 and less than or equal to ' + str(multiprocessing.cpu_count()))
                sys.exit(-1)
        elif command == 'verbose':
            verbose = arg.split('=')[1]
            if verbose in ['0', '1']:
                args['verbose'] = verbose
            else:
                print('invalid input. verbose must be 0(false) or 1(true)')
                sys.exit(-1)
        elif command == 'substring':
            substring = int(arg.split('=')[1])
            if substring > 0 and substring < 27:
                args['substring'] = substring
            else:
                print('invalid input. substring must be greater than 0 and less than 27')
                sys.exit(-1)
        else:
            print('invalid input: ' + command  + '\nrun `python3 plutus.py help` for help')
            sys.exit(-1)
    
    print('reading database files...')
    database = set()
    for filename in os.listdir(DATABASE):
        with open(DATABASE + filename) as file:
            for address in file:
                address = address.strip()
                if address.startswith('1'):
                    database.add(address[-args['substring']:])
    print('DONE')

    print('database size: ' + str(len(database)))
    print('processes spawned: ' + str(args['cpu_count']))
    
    for cpu in range(args['cpu_count']):
        multiprocessing.Process(target = main, args = (database, args)).start()
