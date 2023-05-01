https://stackoverflow.com/questions/52430798/onehotencoder-encoding-only-some-of-categorical-variable-columns

https://stackoverflow.com/questions/37004965/how-to-turn-protocol-number-to-name-with-python

---

To capture all current flows on an interface using Pyshark, you can use a combination of a LiveCapture object and a filter that captures all packets for the interface. Here is an example:

python

import pyshark

# Create a capture object to capture network traffic
capture = pyshark.LiveCapture(interface='eth0')

# Define a filter to capture all packets for the interface
capture.filter = 'not arp'

# Start capturing traffic
capture.sniff()

# Create a dictionary to store all the flows
flows = {}

# Loop through the captured packets and extract information about each flow
for packet in capture:
    # Check if the packet has IP and TCP layers
    if packet.haslayer('IP') and packet.haslayer('TCP'):
        # Extract the 5-tuple from the packet
        src_ip = packet['IP'].src
        dst_ip = packet['IP'].dst
        protocol = packet['IP'].proto
        src_port = packet['TCP'].sport
        dst_port = packet['TCP'].dport
        
        # Create a unique identifier for the flow using the 5-tuple
        flow_id = (src_ip, dst_ip, protocol, src_port, dst_port)
        
        # Check if the flow has been seen before
        if flow_id in flows:
            # Update the flow with the latest packet information
            flows[flow_id]['packets'] += 1
            flows[flow_id]['bytes'] += int(packet.length)
        else:
            # Create a new flow object
            flows[flow_id] = {
                'source_ip': src_ip,
                'destination_ip': dst_ip,
                'protocol': protocol,
                'source_port': src_port,
                'destination_port': dst_port,
                'packets': 1,
                'bytes': int(packet.length)
            }
            
# Print all the flows that were captured
for flow_id, flow_data in flows.items():
    print(f"{flow_data['source_ip']}:{flow_data['source_port']} --> {flow_data['destination_ip']}:{flow_data['destination_port']} Protocol: {flow_data['protocol']} Packets: {flow_data['packets']} Bytes: {flow_data['bytes']}")

In this example, we first create a LiveCapture object for the network interface we want to capture traffic on (eth0 in this case), and then define a filter to capture all packets for the interface, excluding Address Resolution Protocol (ARP) packets.

We then start capturing traffic using the sniff method. For each captured packet, we extract the 5-tuple (source IP, destination IP, protocol, source port, destination port) from the IP and TCP layers of the packet. We then use this 5-tuple as a unique identifier for the flow.

If we have seen the flow before, we update its statistics (number of packets and bytes) with the latest packet information. Otherwise, we create a new flow object and add it to a dictionary that stores all the flows we have seen so far.

Finally, we print out information about all the flows that were captured, including the source and destination IP addresses and port numbers, the protocol, and the number of packets and bytes for each flow.

---