import csv
from pprint import pprint
import socket
import json
import threading
import sys
from retry import retry
from ipaddress import ip_address
from OpenSSL import SSL


def create_log_objects(conn, log_file):
    certificate_chain = []
    if conn.get_peer_cert_chain() is not None:
        for x509 in conn.get_peer_cert_chain():
            json_x509 = {}
            
            json_subject= {}
            for key, value in x509.get_subject().get_components():
                json_subject.update({str(key, "utf-8"): str(value, "utf-8")})

            json_issuer = {}
            for key, value in x509.get_issuer().get_components():
                json_issuer.update({str(key, "utf-8"): str(value, "utf-8")})
            
            json_extension = {}
            for index in range(x509.get_extension_count()):
                extension = x509.get_extension(index)
                json_extension.update({str(extension.get_short_name(), "utf-8"): str(extension)})
            
            json_x509.update({"extension": json_extension})
            json_x509.update({"issuer": json_issuer})
            json_x509.update({"subject": json_subject})

            certificate_chain.append(json_x509)

    servername = None if conn.get_servername() is None else conn.get_servername().decode("utf-8")

    statestring = None if conn.get_state_string() is None else conn.get_state_string().decode("utf-8")
    
    cert = {
    "cipherName": conn.get_cipher_name(),
    "cipherVersion": conn.get_cipher_version(),
    "protocolVersionName": conn.get_protocol_version_name(),
    "servername": servername,
    "shutdown": conn.get_shutdown(),
    "stateString": statestring}

    try:
        dict_log = {"certificateChain":certificate_chain, "cert":cert}
    except Exception as e:
        print("LOG ERROR: ", e)

    try:
        json_out = json.dumps(dict_log, indent=2)
    except Exception as e:
        print("LOG ERROR: ", e)

    log_file.write(json_out)
    log_file.write("\n")

@retry((SSL.WantReadError), tries=25,delay=0.1)
def do_handshake(tls, log_file):
    try:
        tls.do_handshake()
        tls.shutdown()
    except Exception as e:
        print("CONNECTION ERROR: ", e)
    else:
        tls.close()
        create_log_objects(tls, log_file)
    finally:
        tls.close()

def create_connection(ip_address, log_file, context):

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)
    tls = SSL.Connection(context, sock)

    # To surpass connection timeout. May take some time.
    # This catches all exceptions, i.e. also ip addresses that do not exist.
    try:
        tls.connect((ip_address, 443))
    except Exception as e:
        print("CONNECTION ERROR: ",e)
        
    do_handshake(tls, log_file)


def get_ip(check_ip):
    i= check_ip.find('/')
    if i != -1:
        no_subnet_ip = check_ip[:i]
    else:
        no_subnet_ip = check_ip
    
    try:
        ip = str(ip_address(no_subnet_ip))
    except ValueError as e:
        print("IP VALUE ERROR: ", e)
    except Exception as e:
        print("IP ERROR: ", e)
    else:
        return ip
    
    try:
        # Strip off the newline character.
        # Check if valid ip address by 
        print("CHECK IP", check_ip)
        ip = socket.gethostbyname(check_ip[:-1])
        print(ip)
    except socket.gaierror as e:
        print("INVALID HOSTNAME ERROR: ", e)
    except Exception as e:
        print("IP ERROR: ", e)
        return None
    else:
        return ip


def import_blocklist(blocklist_file):
    ip_addresses = []
    with open(blocklist_file, "r") as block_file:
        lines = block_file.readlines()
        for line in lines:
            ip = get_ip(line)
            if ip is not None:
                ip_addresses.append(ip)     
    return ip_addresses

def main(blocklist_file, inputlist_file, rootlist_file, output_file):
    print("Opening files")
    blocklist = import_blocklist(blocklist_file)
    with open(inputlist_file) as csvfile:
        file = csv.reader(csvfile)
        
        print(rootlist_file)

        #In the case that all TLS versions had wanted to be tried, use context.set_max_proto_version and context.set_min_proto_version
        context = SSL.Context(SSL.TLS_CLIENT_METHOD)
        context.load_verify_locations(rootlist_file)
        context.set_verify(SSL.VERIFY_PEER)
        
        i = 0
        with open(output_file, "a") as log_file:
            threads = []
            print("Reading input file")
            for row in file:
                ip = get_ip(row[1])
                if ip is not None and ip not in blocklist:
                    print("Creating connection for {} using {} ".format(ip, log_file)
                    i = i + 1
                    conn_thread = threading.Thread(target=create_connection, args=(ip, log_file,context))
                    threads.append(conn_thread)
                    conn_thread.start()

            for conn_thread in threads:
                conn_thread.join()
        print("Total number of connections: ", i)

if __name__ == "__main__":
    print("Processing command line options")
    #parsing command line arguments
    blocklist = False
    inputlist = False
    rootlist = False
    output = False

    #default files
    blocklist_file="week3-blocklist.txt"
    inputlist_file="week3-input_testing.csv"
    rootlist_file="week3-roots.pem"
    output_file="logs.json"

    for arg in sys.argv:
        if arg == "--blocklist" or arg == "-b":
            blocklist = True
        elif arg == "--inputlist" or arg == "-i":
            inputlist = True
        elif arg == "--rootstore" or arg == "-r":
            rootlist = True
        elif arg == "--outputfile" or arg == "-o":
            output = True
        elif arg == "--help" or arg == "-h":
            print("Valid commandline options are --blocklist (-b) file, --inputlist (-i) file, --rootstore (-r) file, --output (-o) file, --help (-h)")
        elif blocklist:
            blocklist_file = arg
            blocklist = False
        elif inputlist:
            inputlist_file = arg
            inputlist = False
        elif rootlist:
            rootlist_file = arg
            rootlist = False
        elif output:
            output_file = arg
            output = False
    if blocklist or inputlist or rootlist or output:
        raise ValueError("Incorrect argument set. A file has to be specified as an argument after the command line option.")
    else:
        main(blocklist_file, inputlist_file, rootlist_file, output_file)