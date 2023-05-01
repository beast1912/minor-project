import pyshark

# Specify the network interface to capture traffic on
capture = pyshark.LiveCapture(interface='wlp0s20f3')

# Define a filter to capture only traffic of interest
protocols = ['gre', 'icmp', 'icmpv6', 'igmp', 'ipv6', 'tcp', 'udp']
capture.filter = ' or '.join(f'({p})' for p in protocols)

# Start the capture process
capture.sniff(timeout=1)

# Iterate over the captured packets and extract flow information
flows = {}
for packet in capture:

    if 'ip' not in packet:
        continue

    src_ip = packet.ip.src
    dst_ip = packet.ip.dst
    proto = packet.transport_layer if packet.transport_layer in protocols else 'other_proto'
    layer_name = packet.layers[-1].layer_name if proto in ('tcp', 'udp') else None
    src_port = packet[layer_name].srcport if layer_name else None
    dst_port = packet[layer_name].dstport if layer_name else None
    flow_key = (src_ip, dst_ip, proto, src_port, dst_port)
    if flow_key not in flows:
        flows[flow_key] = 0
    flows[flow_key] += 1

# Print the flow information
for flow_key, flow_count in flows.items():
    print(f'Flow: {flow_key}, Packet count: {flow_count}')
