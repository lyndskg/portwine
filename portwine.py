# implement ICMP class. 
# Figure out what sniffer thread (s_thread) vs r_thread is

import errno
import sys
import os
import signal
import ctypes
import queue
import threading
import socket
import datetime
import struct

top_1000_ports = [1,2,3,7,9,13,17,19,20,21,22,23,25,26,37,38,42,49,53,67,68,69,79,80,81,82,88,100,106,110,111,112,113,119,120,123,135,136,137,138,139,143,144,158,161,162,177,179,192,199,207,217,254,255,280,311,363,389,402,407,427,434,443,444,445,464,465,497,500,502,512,513,514,515,517,518,520,539,543,544,548,554,559,587,593,623,625,626,631,636,639,643,646,657,664,682,683,684,685,686,687,688,689,764,767,772,773,774,775,776,780,781,782,786,787,789,800,808,814,826,829,838,873,902,903,944,959,965,983,989,990,993,995,996,997,998,999,1000,1001,1007,1008,1012,1013,1014,1019,1020,1021,1022,1023,1024,1025,1026,1027,1028,1029,1030,1031,1032,1033,1034,1035,1036,1037,1038,1039,1040,1041,1042,1043,1044,1045,1046,1047,1048,1049,1050,1051,1053,1054,1055,1056,1057,1058,1059,1060,1064,1065,1066,1067,1068,1069,1070,1071,1072,1080,1081,1087,1088,1090,1100,1101,1105,1110,1124,1200,1214,1234,1346,1419,1433,1434,1455,1457,1484,1485,1521,1524,1645,1646,1701,1718,1719,1720,1723,1755,1761,1782,1801,1804,1812,1813,1885,1886,1900,1901,1993,1998,2000,2001,2002,2005,2048,2049,2051,2103,2105,2107,2121,2148,2160,2161,2222,2223,2343,2345,2362,2383,2401,2601,2717,2869,2967,3000,3001,3052,3128,3130,3283,3296,3306,3343,3389,3401,3456,3457,3659,3664,3689,3690,3702,3703,3986,4000,4001,4008,4045,4444,4500,4666,4672,4899,5000,5001,5002,5003,5009,5010,5050,5051,5060,5093,5101,5120,5190,5351,5353,5355,5357,5432,5500,5555,5631,5632,5666,5800,5900,5901,6000,6001,6002,6004,6050,6112,6346,6347,6646,6970,6971,7000,7070,7937,7938,8000,8001,8008,8009,8010,8031,8080,8081,8181,8193,8443,8888,8900,9000,9001,9020,9090,9100,9102,9103,9199,9200,9370,9876,9877,9950,9999,10000,10010,10080,11487,16086,16402,16430,16680,16832,16918,16947,17091,17185,17219,17455,17459,17573,17615,17616,17754,17888,17939,17989,18004,18234,18331,18360,18449,18582,18835,18888,18980,19017,19039,19120,19130,19165,19197,19283,19294,19315,19322,19332,19489,19503,19541,19600,19616,19682,19687,19933,20003,20004,20019,20031,20126,20359,20389,21000,21131,21212,21261,21298,21354,21383,21621,21800,21803,21847,21902,22055,22341,22692,22695,22739,22799,22846,22914,22986,22996,23040,23176,23354,23531,23557,23608,23679,23781,23965,23980,24007,24242,24279,24511,24594,24606,24644,24854,24910,25003,25157,25240,25280,25337,25375,25462,25541,25546,25709,25931,26407,26415,26720,26872,26966,27002,27007,27015,27195,27444,27473,27482,27707,27892,27899,28122,28369,28465,28493,28543,28547,28641,28840,28973,29078,29243,29256,29810,29823,29977,30260,30263,30303,30365,30544,30656,30697,30704,30718,30975,31059,31073,31109,31134,31137,31155,31162,31180,31189,31195,31199,31202,31261,31266,31267,31284,31334,31335,31337,31343,31350,31352,31361,31365,31404,31412,31428,31481,31520,31521,31560,31569,31584,31599,31602,31609,31625,31673,31681,31692,31720,31731,31732,31735,31743,31750,31783,31792,31794,31803,31852,31882,31887,31891,31918,31963,31999,32044,32053,32066,32124,32129,32132,32185,32216,32219,32262,32273,32326,32345,32352,32359,32368,32382,32385,32404,32415,32422,32425,32430,32446,32469,32479,32495,32499,32506,32528,32546,32607,32611,32727,32750,32760,32768,32769,32770,32771,32772,32773,32774,32775,32776,32777,32778,32779,32780,32798,32815,32818,32931,33030,33249,33281,33354,33355,33459,33717,33744,33866,33872,34038,34079,34125,34358,34422,34433,34555,34570,34577,34578,34579,34580,34758,34796,34855,34861,34862,34892,35438,35702,35777,35794,36108,36206,36384,36458,36489,36669,36778,36893,36945,37144,37212,37393,37444,37602,37761,37783,37813,37843,38037,38063,38293,38412,38498,38615,39213,39217,39632,39683,39714,39723,39888,40019,40116,40441,40539,40622,40708,40711,40724,40732,40805,40847,40866,40915,41058,41081,41308,41370,41446,41524,41638,41702,41774,41896,41967,41971,42056,42172,42313,42431,42434,42508,42557,42577,42627,42639,43094,43195,43370,43514,43686,43824,43967,44101,44160,44179,44185,44190,44253,44334,44508,44923,44946,44968,45247,45380,45441,45685,45722,45818,45928,46093,46532,46836,47624,47765,47772,47808,47915,47981,48078,48189,48255,48455,48489,48761,49152,49153,49154,49155,49156,49157,49158,49159,49160,49161,49162,49163,49165,49166,49167,49168,49169,49170,49171,49172,49173,49174,49175,49176,49177,49178,49179,49180,49181,49182,49184,49185,49186,49187,49188,49189,49190,49191,49192,49193,49194,49195,49196,49197,49198,49199,49200,49201,49202,49204,49205,49207,49208,49209,49210,49211,49212,49213,49214,49215,49216,49220,49222,49226,49259,49262,49306,49350,49360,49393,49396,49503,49640,49968,50000,50099,50164,50497,50612,50708,50919,51255,51456,51554,51586,51690,51717,51905,51972,52144,52225,52503,53006,53037,53571,53589,53838,54094,54114,54281,54321,54711,54807,54925,55043,55544,55587,56141,57172,57409,57410,57813,57843,57958,57977,58002,58075,58178,58419,58631,58640,58797,59193,59207,59765,59846,60172,60381,60423,61024,61142,61319,61322,61370,61412,61481,61550,61685,61961,62154,62287,62575,62677,62699,62958,63420,63555,64080,64481,64513,64590,64727,65024]

ports_ident =  {
                "open"          : [],
                "closed"        : [],
                "filtered"      : [],
                "open|filtered" : []
                }

VERBOSE            = False
VERBOSE_EXTRA      = False
SCAN_TYPE          = "TCP"
timeout            = 5000
threads            = 10
r_threads          = []
port_states        = []
exit_event         = threading.Event()

# Prints the PortWine banner.
def banner():
    print("")
    print("\t    PortWine v1.0 -- https://github.com/lyndskg")
    print("\t---------------------------------------------------")
    print("\t    A simple, fast, lightweight TCP/UDP scanner")
    print("")

# Prints usage information.
def usage():
	banner() # Banner

	print("Usage: %s -t [targets] -p [ports] [options]" % sys.argv[0])
	print("")

    # Options menu
	print("Options:")
	print("")
	print("\t{:<10} {:<30}".format("-t", "[target hostname]"))
	print("\t{:<10} {:<30} {:<40}".format("-p", "[port]", "Examples: ( -p 25 || -p 22,23,24,25 || -p 0-1024 )"))
	print("\t{:<10} {:<30} {:<40}".format("-s[TU]", "Scan type ( default = -sT )", "Examples: ( -sT : TCP || -sU : UDP )"))
	print("\t{:<10} {:<30}".format("--threads", "Number of threads (Default=10)"))
	print("\t{:<10} {:<30}".format("-v", "Verbose output"))
	print("\t{:<10} {:<30}".format("--timeout", "[timeout in ms]", "(default=5000)"))
	print("")

    # Examples
	print("Examples:")
	print("\n\t%s -sT -t 127.0.0.1 -p 0-65535 -v  - Do a verbose TCP scan of all ports on 127.0.0.1" % sys.argv[0])
	print("\t%s -sU -t 127.0.0.1 -p 0-100       - Do a UDP scan of the first 100 ports on 127.0.0.1" % sys.argv[0])	

# Captures keyboard interruption.
def signal_handler(sig, frame):
    print('You pressed Control-C! Exiting...')
    sys.exit(0)

# Parse the command line argument specifications for ports.
def parse_ports(arg):
    ports = []

    # If a range of ports is specified
    if "-" in arg:
        try:
            start, end = arg.split("-")
            start = int(start)
            end = int(end)

            # If ports are within range
            if (start <= 65535) and (end <= 65535):
                # For TCP, port number 0 is reserved and cannot be used
                # For UDP, the source port is optional and a value of zero means no port
                if SCAN_TYPE == "UDP" and start == 0:
                    start += 1

                # Iterate through and append all in-range ports
                for p in range(start, end + 1):
                    ports.append(p)
            # Else, ports are out of range
            else: 
                print("Ports cannot be higher than 65535.")
                sys.exit(1)
        except:
            print("Error with port specification. e.g. (0-1000)")
            sys.exit(1)

    # If a list of ports is specified
    elif "," in arg:
        try:
            for p in arg.split(","):
                # If ports are in range
                if (int(p) <= 65535):
                    ports.append(int(p))
                # Else, ports are out of range
                else:
                    print("Ports cannot be higher than 65535")
                    sys.exit(1)
        except:
            print("Error with port specification. e.g. (22,23,25)")
            sys.exit(1)

    # If a single port is specified
    else:
        try:
            # If port is in range
            if (int(arg) <= 65535):
                ports.append(int(arg))
            # Else, port is out of range
            else:
                print("Ports cannot be higher than 65535")
                sys.exit(1)
        except:
            print("Error with port specified. See help.")
            sys.exit(1)

    return ports


# Returns the current date and time
def date_time():
    return datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")

class ICMP(ctypes.Structure):
	_fields_ = [
	('type',		 ctypes.c_ubyte),
	('code',		 ctypes.c_ubyte),
	('checksum',     ctypes.c_ushort),
	('unused',       ctypes.c_ushort),
	('next_hop_mtu', ctypes.c_ushort)
	]

	def __new__(self, socket_buffer):
		return self.from_buffer_copy(socket_buffer)

	def __init__(self, socket_buffer):
		pass

# Instantiates the Scanner class
class Scanner(object):
    # Instantiates the TCPScanner sub-class
    class TCPScanner(threading.Thread):
        def __init__(self, target, portqueue):
            threading.Thread.__init__(self)
            self.target = target
            self.portqueue = portqueue
        
        def run(self):
            while 1:
                if self.portqueue.empty() or exit_event.is_set():
                    break
                
                target = self.target
                port = self.portqueue.get()

                try: 
                    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    conn.settimeout(float(timeout / 1000))

                    # Returns an error indicator
                    result = conn.connect_ex((target, port))
                    
                    # Data received -- SYN ACK
                    if result == 0: 
                        if VERBOSE:
                            sys.stdout.write("[%s] %s - %d/tcp open (SYN-ACK packet)\n" % (date_time(), target, port))
                        ports_ident["open"].append(port)
                    
                    # RST received -- Port closed
                    elif result == 111:
                        if VERBOSE_EXTRA:
                            sys.stdout.write("[%s] %s - %d/tcp closed (RST packet)\n" % (date_time(), target, port))
                        ports_ident["closed"].append(port)
                    
                    # ERR Code 11 -- Timeout
                    elif result == 11:
                        if VERBOSE_EXTRA:
                            sys.stdout.write("[%s] %s - %d/tcp filtered (No response)\n" % (date_time(), target, port))
                        ports_ident["filtered"].append(port)
                    
                    else:
                        pass
                
                except Exception as e:
                    # If the connection timed out 
                    if type(e) == socket.timeout:
                        ports_ident["filtered"].append(port)
                    else:
                        if VERBOSE:
                            print(dir(e))
                            print("[%s] Error %s - %s:%s - %s" % (date_time(), e.errno, target, port, e.strerror))

                # Close the connection
                finally:
                    conn.close()

    # Instantiates the UDPScanner sub-class
    class UDPScanner(threading.Thread):
        def __init__(self, target, portqueue):
            threading.Thread.__init__(self)
            self.status = None
            self.target = target
            self.portqueue = portqueue

        # Handles Type 3 error (i.e. EConnection refused)
        def handle_econn_refused(self):
            self.status = False
            self.socket.close() # Close the socket
            
            if VERBOSE_EXTRA:
                sys.stdout.write('UDP port closed.', self.port)
        
        # Handles receipt of packets
        def handle_receive(self):
            self.status = True
            self.socket.close()
            
            if VERBOSE_EXTRA:
                sys.stdout.write('UDP port open.', self.port)

        def run(self):
            while 1:
                if self.portqueue.empty() or exit_event.is_set():
                    break
                
                # If UDP port status is already open or closed
                if self.status is not None: 
                    continue

                target = self.target
                port = self.portqueue.get()
                
                try: 
                    conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    conn.settimeout(float(timeout / 1000))
                    
                    # Connects to target at port
                    conn.connect((target, port))

                    try: 
                        # Attempts to send an arbitrary byte
                        conn.send('\x00')
                    except socket.error as ex:
                        if ex.errno == errno.ECONNREFUSED:
                            self.handle_econn_refused()
                            break
                        else:
                            raise
                    
                    try: 
                        # Receives a response of max 8192 bytes from the socket 
                        d = conn.recvfrom(8192)

                        # If a sizable response was received
                        if (len(d) > 0):
                            if VERBOSE:
                                sys.stdout.write("[%s] %s - %d/udp open (Data recieved)\n" % (date_time(), target, port))
                            ports_ident["open"].append(port)

                        self.handle_receive()
                        continue

                    except socket.error as ex:
                        if ex.errno == errno.ECONNREFUSED:
                            if VERBOSE_EXTRA:
                                sys.stdout.write('UDP recv failed.', self.port)
                            continue
                        elif ex.errno != errno.EAGAIN:
                            if VERBOSE_EXTRA:
                                sys.stdout.write('UDP recv failed.', self.port)
                            raise
                    
                
                except socket.timeout:
                    if port not in ports_ident["closed"]:
                        ports_ident["open|filtered"].append(port)
                
                conn.close()

# Thread sniffer based on a target address
def sniffer_thread(target):
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    sniffer.bind(("0.0.0.0", 0))
    sniffer.settimeout(1)
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

	# Continually read in packets and parse their information
    while True:
        if (exit_event.is_set()):
            break
        
        try:
            raw_buffer = sniffer.recvfrom(65565)[0]		
            ip_header = raw_buffer[0:20]
            dst_port = struct.unpack(">h", raw_buffer[0x32:0x34])[0]
            iph = struct.unpack('!BBHHHBBH4s4s', ip_header)

			# Create our IP structure
            version_ihl = iph[0]
            ihl = version_ihl & 0xF
            iph_length = ihl * 4
            src_addr = socket.inet_ntoa(iph[8])

			# Create our ICMP structure
            buf = raw_buffer[iph_length:iph_length + ctypes.sizeof(ICMP)]
            icmp_header = ICMP(buf)

			# check for the type 3 and code and within our target subnet
            if icmp_header.code == 3 and icmp_header.type == 3 and src_addr == target:
                if dst_port not in ports_ident["closed"]:
                    ports_ident["closed"].append(dst_port)
        
        except Exception as e:
            pass
    

# Returns the state of all ports
def get_states(msg, n):
    return "%d %s ports." % (n, msg)


# Prints results on the target address
def print_results(target):
    if VERBOSE:
        print("")
    
    print('{:<15} {:<15} {:<15}'.format("Port", "State", "Reason"))
    print("-----------------------------------------------------")
    
    the_dict = ports_ident.items()

    # Iterate through each state and port list in the dictionary 
    for state, p_list in the_dict:
        # If the length of the port list is greater than 20, append a state summary
        if (len(p_list) > 20):
            port_states.append(get_states(state, len(p_list)))
        else:
            for port in p_list:
                if state == "open":
                    if SCAN_TYPE == "UDP":
                        print('{:<15} {:<15} {:<15}'.format("%d/%s" % (port, SCAN_TYPE.lower()), state, "Data recieved"))
                    else:
                        print('{:<15} {:<15} {:<15}'.format("%d/%s" % (port, SCAN_TYPE.lower()), state, "syn-ack"))
                elif state == "filtered":
                    print('{:<15} {:<15} {:<15}'.format("%d/%s" % (port, SCAN_TYPE.lower()), state, "timeout"))
                elif state == "open|filtered":
                    print('{:<15} {:<15} {:<15}'.format("%d/%s" % (port, SCAN_TYPE.lower()), state, "timeout"))
                elif state == "closed":
                    if SCAN_TYPE == "UDP":
                        print('{:<15} {:<15} {:<15}'.format("%d/%s" % (port, SCAN_TYPE.lower()), state, "ICMP Code 3"))
                    else:
                        print('{:<15} {:<15} {:<15}'.format("%d/%s" % (port, SCAN_TYPE.lower()), state, "rst"))


# Main function
if __name__ == '__main__':
    # If verbose mode is selected
    if "-v" in sys.argv:
        VERBOSE = True
    
    # If extra verbose mode is selected
    if "-vv" in sys.argv or "-vvv" in sys.argv:
        VERBOSE_EXTRA = True

    # If the help menu is selected
    if "-h" in sys.argv or "--help" in sys.argv:
        usage()
        sys.exit(0)

    # If a UDP scan is selected
    if "-sU" in sys.argv:
        if os.geteuid() != 0:
            sys.exit("You need root permissions to do a UDP scan.")
            SCAN_TYPE = "UDP"
    
    # If a timeout value (in ms) is specified
    if "--timeout" in sys.argv:
        try: 
            timeout = float(sys.argv[sys.argv.index("--timeout") + 1])
        except:
            print("Error with supplied timeout value.")
            sys.exit(1)

    # If the number of threads (default = 10) is specified
    if "--threads" in sys.argv:
        try: 
            threads = int(sys.argv[sys.argv.index("--threads") + 1])
        except:
            print("Error with supplied threads value.")
            sys.exit(1)

    # If the ports are specified
    if "-p" in sys.argv:
        ports = parse_ports(sys.argv[sys.argv.index("-p") + 1])
    else:
        ports = top_1000_ports

    # If the target hostname is not specified
    if "-t" not in sys.argv:
        usage()
        sys.exit(1)

    # Print the banner.
    banner()

    # Handles signal. 
    signal.signal(signal.SIGINT, signal_handler)
    
    # Target hostname is initialized to argv parameter following "-t."
    target = sys.argv[sys.argv.index("-t") + 1]

    q = queue.Queue()

    # Try to get target IP address from target hostname.
    try:
        ip_target = socket.gethostbyname(target)
    # Exit if hostname cannot be resolved.
    except: 
        print("[%s] Could not resolve host: '%s'" % (date_time(), target))
        sys.exit(1)

    
    # Iterate through all ports, adding each to the queue
    for p in ports:
        q.put(p)
    
    print("[%s] Scan started - Host: %s (%s)" % (date_time(), target, ip_target))

    # If UDP scan is selected
    if SCAN_TYPE == "UDP":
        s_thread = threading.Thread(target=sniffer_thread, args=(ip_target,))
        s_thread.daemon = True
        s_thread.start()
	
    # If fewer ports than threads, set # of threads equal to # of ports
    if (len(ports) < threads):
        threads = len(ports)

    # Iterate through each thread in threads
    for x in range(threads):
        # If TCP scan is selected
        if SCAN_TYPE == "TCP":
            r_threads.append(Scanner.TCPScanner(ip_target, q))
        # If UDP scan is selected
        elif SCAN_TYPE == "UDP":
            r_threads.append(Scanner.UDPScanner(ip_target, q))

    # Iterate through each thread in r_threads
    for thread in r_threads:
        thread.daemon = True
        thread.start()
	
    # Iterate through each thread in r_threads, again
    for thread in r_threads:
        thread.join()

    # Print results
    print_results(ip_target)
	
    # Print port states summary.
    for p in port_states:
        print(p)
    
    print("\n[%s] Scan finished.\n" % (date_time()))
