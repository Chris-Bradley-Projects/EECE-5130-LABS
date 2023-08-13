# EECE-5550-LAB#3 Packet Sniffing and Spoofing Lab

### Title and Author

* **Title:** *EECE Packet Sniffing and Spoofing Lab*
* **Author:** *Christopher Bradley*

### Purpose of Packet Sniffing and Spoofing lab

* The Purpose of this lab is to learn how to use the tools related to packet sniffing and spoofing and understanding the technologies undelying these tools. For the second objective is to write simple sniffer and spoofing programs, and gain an in-depth understanding of the technical aspects of these programs. This lab covers the following topics:
  - How the sniffing and spoofing work
  - Packet sniffing using the pcap library and Scapy
  - Packet spoofing using raw socket and Scapy
  - Manipulating packets using Scapy

**File Overview:**

* Labsetup - This folder contains all the machines needed for the attacker when spoofing and sniffing packets.
* Task1-1.py - Contains the code for the initial example of task 1A
* Task1-1B.py - Contains the code for task 1B
* Task1-2.py - Contains the python code for task 1.2
* Task1-3.py - Contains the python code for task 1.3
* Task1-4.py - Contains the python code for task 1.4

* Task2-1A.c - Contains the C code for task 2.1A
* Task2-1B.c - Contains the C code for task 2.1B
* Task2-1C.c - Contains the C code for task 2.1C
* Task2-2A.c - Contains the C code for task 2.2A
* Task2-2B.c - Contains the C code for task 2.2B
* Task2-3.c - Contains the C code for task 2.3

**Code SnapShots and Explanation**
* Tasks #1-1
  * Below shows the first example code used for packet sniffing.
    * ![Packet Sniffing](/Images/LAB3/Task1-1.png)
  * Part A: Below shows the output with sudo vs not with sudo. When I ran the program with root privlileges I saw the packets from the ping being printed out to the console. When I run it without root privliges I get an error that says "Operation not permitted" this is becasue root privliges are required to sniff the packets.
    * ![With Sudo](/Images/LAB3/Task1-1A.png)
    * ![Without Sudo](/Images/LAB3/Task1-1A_part2.png)
  * Part B: Below shows the code for applying the filters to the sniffer. The first photo is for the TCP filter code and the second filter is for the subnet filter code. The third photo shows the output.
    * ![TCP filter code](/Images/LAB3/Task1-1B.png)
    * ![subnet filter code](/Images/LAB3/Task1-1B_part2_code.png)
    * ![subnet filter output](/Images/LAB3/Task1-1B_part2.png)
* Tasks #1-2
  * Below shows the code used to spoof a packet and the output of the program.
    * ![Spoof code](/Images/LAB3/Task1-2.png)
    * ![Spoof output](/Images/LAB3/Task1-2_output.png)
* Tasks #1-3
  * Below shows the code used to traceroute a packet and the output of the traceroute. As you can see from the second photo it took 15 routers to get to the destination.
    * ![Traceroute code](/Images/LAB3/Task1-3.png)
    * ![Number of routers](/Images/LAB3/Task1-3_output.png)
* Tasks #1-4
  * Below shows the code for sniffing and then spoofing a packet.
    * ![sniff and spoof code](/Images/LAB3/Task1-4.png)
  * Part 1: When I pinged 1.2.3.4 on the attacker side where the code was running you were able to see the original packet and spoofed packets get printed to the console.
    * ![Address 1.2.3.4](/Images/LAB3/Task1-4_Part1.png)
  * Part 2: Since this address does not exists on the LAN when we try to ping it we get a Destination Host unreachable error.
    * ![Address 10.0.0.99](/Images/LAB3/Task1-4_Part2.png)
  * Part 3: This is already an exsisting host so we are getting DUP packets when spoofing indicated by the (DUP!)
    * ![Address 8.8.8.8](/Images/LAB3/Task1-4_Part3.png)

* Tasks #2-1
  * Part A: Below shows the code used to sniff a packet and print out the dest IP of each captured packet. The second photo is the output when you run the code. The third photo shows the ping used to generate the packets.
    * ![Sniffer Part A Code](/Images/LAB3/Task2-1A.png)
    * ![Sniffer Part A Output](/Images/LAB3/Task2-1A_output.png)
    * ![Sniffer Part A Output](/Images/LAB3/Task2-1A_ping.png)
    - Question #1:
      - A sniffer program is used to capture network traffic. Essential library calls in sequence for such programs (using the pcap library) include the following:
        pcap_open_live(): 
          - This call is used to open a network device for capturing traffic. It returns a handle that's used in subsequent calls.
        pcap_compile(): 
        - Converts a human-readable filter expression into a format that can be used by the pcap library to filter packets.
        pcap_setfilter(): 
        - Applies the compiled filter to the capture, so only desired packets (those matching the filter) are captured.
        pcap_loop(): 
        - Captures packets, either indefinitely or a specific number of packets. As packets are captured, a provided callback function is invoked to process each one.
        pcap_close(): 
        - Closes the capture handle, effectively ending the capture session.
    - Question #2:
      - Root privileges are required because raw packet capturing can potentially expose all the traffic passing through a network interface, which poses security and privacy risks. If executed without root privliges the program would not be able to open the network device for packet capture.
    - Question #3:
      - Promiscuous mode is a mode in which a network interface captures all packets it sees, regardless of the destination of the packets. Normally, a network card only captures packets addressed to its MAC address. When in promiscuous mode, it captures all packets it can see. I can demonstrate the difference by setting up a scenario where there are multiple devices communicating on the same network. When the sniffer program is not in promiscuous mode, it will only capture traffic directed to its own MAC address. When in promiscuous mode, it will capture all traffic it can see on the network.
  * Part B: Below shows the code used to create filters for the sniffer.
    * ![Sniffer Filter Code](/Images/LAB3/Task2-1B.png)
    * Part 1: The first photo is the output for the ICMP filter and the second photo shows the ping used to generate the packets.
      * ![Sniffer output filter 1](/Images/LAB3/Task2-1B_Part1_Output.png)
      * ![Sniffer ping filter 1](/Images/LAB3/Task2-1B_Part1_Ping.png)
    * Part 2: The first photo is the output for the TCP filter the second and thrid photos show how I created the listener and netcat to generate the packets.
      * ![Sniffer output filter 2](/Images/LAB3/Task2-1B_Part2_Output.png)
      * ![Sniffer listener filter 2](/Images/LAB3/Task2-1B_Part2_listener.png)
      * ![Sniffer netcat filter 2](/Images/LAB3/Task2-1B_Part2_netcat.png)
  * Part C: Below shows the code used to sniff a password from telnet. The second photo shows the output of the code and the third photo shows the telnet login request used to generate the packets.
    * ![Sniffing password code](/Images/LAB3/Task2-1C.png)
    * ![Sniffing passsword output](/Images/LAB3/Task2-1C_Output.png)
    * ![Sniffing password telnet](/Images/LAB3/Task2-1C_telnet.png)
* Tasks #2-2
  * Part A: Below shows the code used to spoof a packet and the output of the spoofed program. The second photo shows a wireshark capture of the spoofed packet.
    * ![Spoofing code](/Images/LAB3/Task2-2A.png)
    * ![Spoofing output](/Images/LAB3/Task2-2A_output.png)
    * ![Spoofing wireshark](/Images/LAB3/Task2-2A_Wireshark.png)
  * Part B: Below shows the code for the spoofed echo request packet. The second photo shows the output of the spoofed echo program. The third photo shows the wireshark capture of the spoofed echo request packet.
    * ![spoof echo code](/Images/LAB3/Task2-2B.png)
    * ![spoof echo output](/Images/LAB3/Task2-2B_Output.png)
    * ![Spoof echo wireshark](/Images/LAB3/Task2-2B_WireShark.png)
* Tasks #2-3
  * Below shows the code used to sniff and spoof a packet. The second photo shows the output of the sniffed and spoofed program. The third photo shows the ping used to generate the packets and it shows that a reply is sent back (spoofed) even though there is no actual reply from the machine.
    * ![Sniff and Spoof code](/Images/LAB3/Task2-3.png)
    * ![Sniff and Spoof output](/Images/LAB3/Task2-3_Output.png)
    * ![Sniff and Spoof ping](/Images/LAB3/Task2-3_Ping.png)