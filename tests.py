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


if __name__ == '__main__':
    unittest.main()