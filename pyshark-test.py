import pyshark


capture = pyshark.LiveCapture(interface='wlp0s20f3')
capture.sniff(timeout=0.5)

print(capture)


for packet in capture:
    protocol = packet.layers[1].layer_name if packet.layers else "Unknown"
    print("------")
    for layer in packet.layers:
       print(layer.layer_name)
    print("-----")