import unittest
from port_scan import *
from brute_force import *
from crack_hash import *


def test_beginning(self):
    print('Running test: {} '.format(unittest.TestCase.id(self)))


# Port scan tests
class test_port_scanning(unittest.TestCase):

    def test_splitting_port_arg(self):
        test_beginning(self)

        # Invalid port
        with self.assertRaises(SystemExit):
            ports = split_ports('test')

        # Data structure for port
        with self.assertRaises(SystemExit):
            ports = split_ports((1,7,8,'test'))

        # Actual port
        ports = split_ports('80')
        self.assertEqual(ports, (80,))

        # Ports
        ports = split_ports('22,80,443')
        self.assertEqual(ports, [22,80,443])

        # Port range
        ports = split_ports('20-25')
        self.assertEqual(ports, [20,21,22,23,24,25])

        # Invalid port range
        with self.assertRaises(SystemExit):
            ports = split_ports('20-test')


    def test_single_port_check(self):
        '''
        The port is assumed to be an int. The single port function is only supposed
        to be called after the split ports function. The split ports function performs
        the input validation.
        '''
        test_beginning(self)
        
        # Single port
        single_port = single_port_check((80,))
        self.assertTrue(single_port)

        # Multiple ports
        single_port = single_port_check((22,53,80))
        self.assertFalse(single_port)


    def test_validate_host(self):
        test_beginning(self)

        # Invalid DNS name (random string)
        with self.assertRaises(SystemExit):
            validate_host('qwerqwerqytewqryqewrqwhwkeroikgeawuojuojbgijueaqbi')
        
        # Invalid IP
        with self.assertRaises(SystemExit):
            validate_host('1.1.1.1.1.1.1.1.1.7')

        # Too many numbers to be an IP in decimal form
        with self.assertRaises(SystemExit):
            validate_host(1234163462567437374572740438725803208475803728045380274050823)
        
        # Data structure
        with self.assertRaises(SystemExit):
            validate_host((1,7,8,'test'))

        # Valid DNS name
        target_host = validate_host('localhost')
        self.assertEqual(target_host, '127.0.0.1')

        # Valid IP
        target_host = validate_host('127.0.0.1')
        self.assertEqual(target_host, '127.0.0.1')

        # Random IPv6 address in decimal form
        target_host = validate_host(123416346256)
        self.assertEqual(target_host, '::1c:bc2f:fe90')

        # Loopback address in decimal form
        target_host = validate_host('2130706433')
        self.assertEqual(target_host, '127.0.0.1')




# Brute forcer tests
class test_brute_force_support(unittest.TestCase):


    def test_protocol_splitting(self):
        test_beginning(self)

        # Valid host without protocol
        with self.assertRaises(SystemExit):
            split_protocol_and_host('127.0.0.1')

        # Invalid data
        with self.assertRaises(SystemExit):
            split_protocol_and_host(27)

        # Invalid data structure
        with self.assertRaises(SystemExit):
            split_protocol_and_host((1,7,8,'test'))

        # Valid protocol and target
        protocol, target_host = split_protocol_and_host('ssh://127.0.0.1')
        self.assertEqual(protocol, 'ssh')
        self.assertEqual(target_host, '127.0.0.1')

        # Invalid protocol and valid target. Should still pass. Protocol
        # validation is performed by another function.
        protocol, target_host = split_protocol_and_host('www://127.0.0.1')
        self.assertEqual(protocol, 'www')
        self.assertEqual(target_host, '127.0.0.1')



    def test_protocol_normalization(self):
        test_beginning(self)

        # Invalid protocol
        with self.assertRaises(SystemExit):
            normalize_protocol(12345)

        # Invalid data structure
        with self.assertRaises(SystemExit):
            normalize_protocol((1,7,8,'test'))

        # Valid protocol
        protocol = normalize_protocol('SSH')
        self.assertEqual(protocol, 'ssh')

        # Valid protocol
        protocol = normalize_protocol('SsH')
        self.assertEqual(protocol, 'ssh')

        # Random string. Still should pass. Protocol validation
        # is performed by another function.
        protocol = normalize_protocol('tEsT')
        self.assertEqual(protocol, 'test')



    def test_protocol_validation(self):
        test_beginning(self)

        # Unsupported protocol
        with self.assertRaises(SystemExit):
            validate_protocol('abc')
        
        # Random large number. Not protocol.
        with self.assertRaises(SystemExit):
            validate_protocol(1235416432)

        # Supported protocol
        protocol = validate_protocol('ssh')
        self.assertEqual(protocol, {'protocol': 'ssh', 'port': 22})

        # Supported protocol
        protocol = validate_protocol('ftp')
        self.assertEqual(protocol, {'protocol': 'ftp', 'port': 21})



    def test_target_validation(self):
        '''
        The port is assumed to either be false or a string. This is because
        argparse stores the port variable as False by default or a string type
        if an argument is passed.
        '''
        test_beginning(self)

        # Invalid target with syntactically correct protocol specification
        with self.assertRaises(SystemExit):
            target_specification = validate_target('abc://123', 'test')
        
        # Valid target with invalid port
        with self.assertRaises(SystemExit):
            target_specification = validate_target('ssh://127.0.0.1', 'test')

        # Invalid target without protocol
        with self.assertRaises(SystemExit):
            target_specification = validate_target('testing', '125')

        # Valid target
        target_specification = validate_target('ssh://127.0.0.1', False)
        self.assertEqual(target_specification, {'protocol': 'ssh', 'port': 22, 'target_host': '127.0.0.1'})

        # Valid target with custom port
        target_specification = validate_target('ssh://127.0.0.1', '2222')
        self.assertEqual(target_specification, {'protocol': 'ssh', 'port': 2222, 'target_host': '127.0.0.1'})

        # Valid target with port range
        with self.assertRaises(SystemExit):
            target_specification = validate_target('ssh://127.0.0.1', '20-25')

        # Valid target with multiple ports
        with self.assertRaises(SystemExit):
            target_specification = validate_target('ssh://127.0.0.1', '21,22,25')


# Hash cracking tests
class test_hash_cracking(unittest.TestCase):

    def test_hash_generation(self):
        '''
        Commands used to generate test hashes:
        NTLM: https://codebeautify.org/ntlm-hash-generator
        MD5: echo -n 'baseball12345' | md5sum
        SHA1: echo -n 'baseball12345' | sha1sum
        SHA224: echo -n 'baseball12345' | sha224sum
        SHA256: echo -n 'baseball12345' | sha256sum
        SHA384: echo -n 'baseball12345' | sha384sum
        SHA512: echo -n 'baseball12345' | sha512sum
        SHA3_224: echo -n 'baseball12345' | openssl dgst -sha3-224
        SHA3_256: echo -n 'baseball12345' | openssl dgst -sha3-256
        SHA3_384: echo -n 'baseball12345' | openssl dgst -sha3-384
        SHA3_512: echo -n 'baseball12345' | openssl dgst -sha3-512
        '''

        test_beginning(self)

        hash_input = 'baseball12345'.encode()

        ntlm_hash = ntlm('baseball12345')
        self.assertEqual(ntlm_hash, '15d20bb5a8a7c13882eb179514f640d3')

        md5_hash = md5(hash_input)
        self.assertEqual(md5_hash, '4f1a265431269fca7cc1cf7de92e608d')

        sha1_hash = sha1(hash_input)
        self.assertEqual(sha1_hash, 'c5cc1a7f95e3a2d8d98bf2e579100019f7279ef1')

        sha224_hash = sha224(hash_input)
        self.assertEqual(sha224_hash, '4f97ef09cd9ee0803a89efd838908c91f2e4d7ff783041409d581e86')

        sha256_hash = sha256(hash_input)
        self.assertEqual(sha256_hash, '7130b1ffb6c776db47845f2f338e94f327940beb68840aae985c2f903d156963')

        sha384_hash = sha384(hash_input)
        self.assertEqual(sha384_hash, '5213b56384d59f953ec4fa75e61a467faf6ea791da54b071b8985d1fd6a54423246ede3a29dd38bc6a4471878b7a414b')

        sha512_hash = sha512(hash_input)
        self.assertEqual(sha512_hash, '62b13f88964796073f269a00388d0f58a4996b5c0ad8fa2f2791d067935185e127b21643e8661a6389a95bb5685f89d8601e412adb77f3defa27f3b9fcf620b1')

        sha3_224_hash = sha3_224(hash_input)
        self.assertEqual(sha3_224_hash, '5e5d0def6d4941686b30e4a2618eb26d1741043d80217747b623df56')

        sha3_256_hash = sha3_256(hash_input)
        self.assertEqual(sha3_256_hash, '44125c4b1b06c0cf687166dd5b4e992a1d5212afd196e5a338e4fca44922e895')

        sha3_384_hash = sha3_384(hash_input)
        self.assertEqual(sha3_384_hash, 'dced9bd897c36b12a4729ebc92844e40b0944740c0660c5b87e433d176ed06f68ae9b6369faf2c4ce17d63fd4b9416ac')

        sha3_512_hash = sha3_512(hash_input)
        self.assertEqual(sha3_512_hash, 'e8db926f562c08bdc321df5b1222f2ebafdfcc6991fa1b20007d62a68c11034307081d9177133580c3861ec4fa2d28676cc564cfe5a215efce7f94d6af992971')



if __name__ == '__main__':
    unittest.main()