import argparse
import json
import nmap
import subprocess

def get_hostname(ip_address):
    try:
        output = subprocess.check_output(['nslookup', ip_address]).decode('utf-8')
        start_index = output.index('name = ') + len('name = ')
        end_index = output.index('\n', start_index)
        hostname = output[start_index:end_index].strip()
        return hostname
    except subprocess.CalledProcessError:
        return "N/A"

def read_ip_ranges(filename):
    ip_ranges = []
    with open(filename, 'r') as file:
        for line in file:
            ip_range = line.strip()
            ip_ranges.append(ip_range)
    return ip_ranges

def scan_ip_ranges(ip_ranges):
    nm = nmap.PortScanner()
    scan_results = []

    for ip_range in ip_ranges:
        nm.scan(ip_range, arguments='-sV')

        for host in nm.all_hosts():
            print(f"Starting scan on {host} ...")
            hostname = get_hostname(host)
            host_data = {'Host': host, 'Hostname': hostname, 'Ports': [], 'Comments': ''}
            for port in nm[host].all_tcp():
                service = nm[host]['tcp'][port]['name']
                version = nm[host]['tcp'][port]['version']
                port_data = {'Port': port, 'Service': service, 'Version': version}
                host_data['Ports'].append(port_data)
            scan_results.append(host_data)
            print(f"Finished scan on {host}.")

    return scan_results

# Create the argument parser
parser = argparse.ArgumentParser(description='LAN IP Range Scanner')
parser.add_argument('-i', '--input', metavar='input_file', type=str, required=True, help='input file containing IP ranges')
parser.add_argument('-o', '--output', metavar='output_file', type=str, required=True, help='output file for JSON results')

# Parse the command-line arguments
args = parser.parse_args()

# Read the IP ranges from the file
ip_ranges = read_ip_ranges(args.input)

# Scan the IP ranges
scan_results = scan_ip_ranges(ip_ranges)

# Generate the output dictionary
output = {'hosts': scan_results}

# Save the JSON output to the specified file
with open(args.output, 'w') as json_file:
    json.dump(output, json_file, indent=4)
