#!/usr/bin/python3
import socket
import argparse
from ipaddress import ip_address
from termcolor import colored


def grab_banner(target_host, target_port):
	"""Open a TCP connection to the target host:port and read data (service banner)."""
	try:
		socket.setdefaulttimeout(2)
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.connect((target_host, target_port))

		banner = sock.recv(2048)
		return banner	

	except:
		return False


def scan_port(target_host, target_port, banner, print_closed_ports):
	"""Attempt to connect to an open TCP port on the target host. Try to grab the service banner if requested."""
	try:
		# Try to connect to the target
		socket.setdefaulttimeout(2)
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.connect((target_host, target_port))
		
		if banner:
			print(colored("[+] {}/tcp: Open     Service Banner: {}".format(target_port, banner), 'green'))
		
		else:
			print(colored("[+] {}/tcp: Open".format(target_port), 'green'))

		
	except:
		if print_closed_ports:
			print(colored("[!] {}/tcp: Closed".format(target_port), 'magenta'))

	finally:
		sock.close()


def validate_host(target_host):
	"""Verify the target host argument is an IPv4 resovable hostname or IP address."""
	try:
		resolved_host = socket.gethostbyname(target_host)
		return resolved_host

	except:
		# Validate host is valid IPv4 address
		try:
			ip_address(target_host)
			return target_host

		# No resolable host or valid IPv4 address
		except ValueError:
					print(colored("[!!] Unknown host: {}".format(target_host), 'red'))
					exit(0)


def scan_ports(target_host, target_ports, single_port=False, get_banner=False, display_closed_ports=False):
		"""Initiate scanning of all target ports on designated target host."""
		target_host = validate_host(target_host)
		print("[+] Scan results for: {}".format(target_host))


		# Only single port to scan
		if single_port:

			# Grab service banner if requested
			if get_banner:
				banner = grab_banner(target_host, target_ports)
			
			# Scan single port on target host
			scan_port(target_host, target_ports, banner, display_closed_ports)


		# Multiple ports to scan
		else:
			for target_port in target_ports:

				# Grab service banner if requested
				if get_banner:
					banner = grab_banner(target_host, target_port)

				# Scan single port on target host
				scan_port(target_host, target_port, banner, display_closed_ports)
		



def validate_ports(target_ports):
	"""Verify passed port arguments are integers."""
	validated_target_ports = []
	bad_ports = False
	single_port = False

	# If there's only 1 port
	if len(target_ports) == 1:
		try:
			# Verify port argument is an int
			validated_port = int(target_ports[0])
			single_port = True
			return validated_port, single_port
		
		# Invalid port argument
		except ValueError:
			bad_ports = True

	# If multiple ports
	else:
		for port in target_ports:
			try:
				# Verify port argument is an int
				validated_port = int(port)
				validated_target_ports.append(validated_port)

			# Invalid port argument
			except ValueError:
				bad_ports = True
				break
		
		# Print warning about bad port argument(s) and quit
		if bad_ports:
			print(colored("[!!] invalid port's specified: {}".format(target_ports), 'red'))
			exit(1)
		
		# Returns list of containing each port as an int type and a bool representing whether a only a single port was passed.
		else:
			return validated_target_ports, single_port



def split_ports(target_ports):
	"""Split a list of ports seperated by commas or expand a passed port range."""

	# Comma seperated list of ports
	if ',' in target_ports:
		
		target_ports = target_ports.split(",")
		return target_ports

	# Port range that needs to be expanded
	if '-' in target_ports:
		port_start_and_end = target_ports.split('-')
		expanded_port_range = []

		# Verify both ends of port range are valid
		validate_ports(port_start_and_end)

		# Expand port range
		# Add 1 to the end of the port range to be inclusive of last port
		for port in range(int(port_start_and_end[0]), int(port_start_and_end[1]) + 1):
			expanded_port_range.append(port)
		
		return expanded_port_range

	else:
		
		return (target_ports,)



def main():
	parser = argparse.ArgumentParser(add_help=True)
	parser.add_argument("target_host", help="Specify target host", type=str)
	parser.add_argument("-p", default='1-1023', dest="target_ports", help="Specify target port, ports separated by commas, or port range (ex. 20-23). If a port isn't specified, this script will scan ports 1-1023 by default.", type=str)
	parser.add_argument('-b', action='store_true', dest='get_banner', help='Enable banner grabbing from open ports. Banner grabbing is disabled by default.', default=False)
	parser.add_argument('-c', action='store_true', dest='display_closed_ports', help='Show closed ports. Display of closed ports is disabled by default', default=False)
	args = parser.parse_args()

	target_ports = split_ports(args.target_ports)

	target_ports, single_port = validate_ports(target_ports)
	
	if single_port:
		scan_ports(args.target_host, target_ports, single_port=True, get_banner=args.get_banner, display_closed_ports=args.display_closed_ports)

	else:
		scan_ports(args.target_host, target_ports, get_banner=args.get_banner, display_closed_ports=args.display_closed_ports)

		



if __name__ == '__main__':
	main()

