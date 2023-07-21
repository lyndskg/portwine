# portwine

<p align="center">
<img width="600" alt="Port Scanning" src="https://www.networkcomputing.com/sites/default/files/image%202_3.jpg"> 
</p>

<p align="center">
    A diagram modeling the TCP interactions that take place when a zombie host is used to scan an open port.
</p>

## Overview 

<ins>__Language__</ins>: Python3  

<ins>__Completed on__</ins>: February 3rd, 2023

<b>portwine</b> is a light-weight yet multi-threaded port scanner with support for both UDP and TCP protocols. It probes a server or host for open, closed, and/or filtered ports. Moreover, it can be run on any arbitrary ports of your choosing &mdash; taking in a list or range of ports as an optional command line argument. Otherwise, <b>portwine</b> defaults its scanning space to the top 1000 ports. 

Built using the ["socket"](https://docs.python.org/3/library/socket.html) Python library, with additional support from Python's ["threading"](https://docs.python.org/3/library/threading.html) and ["queue"](https://docs.python.org/3/library/queue.html) libraries for threaded programming functionalities. 

Implementation was largely inspired by [M57's PieScan](https://github.com/m57/piescan/blob/master/piescan.py) and [Remzmike's KPorts](https://github.com/remzmike/python-kports-portscanner/blob/master/kports.py).

## To Do

PortWine is fully implemented, but still needs to be tested and debugged.

## Usage

Simply run "portwine.py" on the command line. The program takes <b>one mandatory</b> (*i.e.* the target IP) and <b>five optional</b> (*i.e.* port number(s), scan type, number of threads, verbose mode, timeout) command line arguments. 

It should look something like this:

```
root@ip # ./portwine.py 

          portwine v1.0 -- https://www.github.com/lyndskg
        ---------------------------------------------------
            A simple, fast, lightweight TCP/UDP scanner

Usage: portwine.py -t [targets] -p [ports] [options]

Options:

        -t         [target ip]
        -p         [port]                         Examples: ( -p 25 || -p 22,23,24,25 || -p 0-1024 )
        -s[TU]     Scan type ( default = -sT )    Examples: ( -sT : TCP || -sU : UDP )
        --threads  Number of threads (Default=10)
        -v         Verbose output
        --timeout  [timeout in ms]

Examples:

        portwine.py -sT -t 127.0.0.1 -p 0-65535 -v  - Do a verbose TCP scan of all ports on 127.0.0.1
        portwine.py -sU -t 127.0.0.1 -p 0-100       - Do a UDP scan of the first 100 ports on 127.0.0.1
```


# Example TCP scan of some specific ports

```
# portwine.py -t google.com -v -p 80,443,21,22

          portwine v1.0 -- https://www.github.com/lyndskg
        ---------------------------------------------------
            A simple, fast, lightweight TCP/UDP scanner

[28/06/2021 21:10:14] Scan started - Host: google.com (172.217.169.46)
[28/06/2021 21:10:14] 172.217.169.46 - 443/tcp open (SYN-ACK packet)
[28/06/2021 21:10:14] 172.217.169.46 - 80/tcp open (SYN-ACK packet)

Port            State           Reason
-----------------------------------------------------
22/tcp          filtered        timeout
21/tcp          filtered        timeout
443/tcp         open            syn-ack
80/tcp          open            syn-ack

[28/06/2021 21:10:19] Scan finished.
```

# Example UDP scan of top 1000 ports

```
# sudo python3 portwine.py -sU -t 1.uk.pool.ntp.org -v --timeout 500 --threads 20
[sudo] password for xxx:

          portwine v1.0 -- https://www.github.com/lyndskg
        ---------------------------------------------------
            A simple, fast, lightweight TCP/UDP scanner

[28/06/2021 21:13:44] Scan started - Host: 1.uk.pool.ntp.org (162.159.200.1)
[28/06/2021 21:13:45] 162.159.200.1 - 123/udp open (Data recieved)

Port            State           Reason
-----------------------------------------------------
123/udp         open            Data recieved
909 open|filtered ports.

[28/06/2021 21:14:07] Scan finished.
```
