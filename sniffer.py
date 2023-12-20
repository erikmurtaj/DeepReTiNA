from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime, timedelta

class Sniffer:
    def __init__(self, flow_timeout=0.6):  # Set default flow timeout to 600 milliseconds
        self.start_time = None
        self.flow_timeout = timedelta(seconds=flow_timeout)
        self.flow_data = {
            "duration": 0,
            "protocol": "",
            "dest_port": 0,
            "forward_packets": 0,
            "backward_packets": 0,
            "forward_size": 0,
            "avg_size_forward": 0,
        }

    def packet_callback(self, packet):
        if packet.haslayer("IP"):
            src_ip = packet["IP"].src
            dst_ip = packet["IP"].dst

            if packet.haslayer("TCP"):
                protocol = "TCP"
                dest_port = packet["TCP"].dport
            elif packet.haslayer("UDP"):
                protocol = "UDP"
                dest_port = packet["UDP"].dport
            else:
                protocol = "Other"
                dest_port = 0

            direction = "forward" if src_ip < dst_ip else "backward"

            if self.start_time is None:
                self.start_time = datetime.now()

            # Check for flow timeout
            if datetime.now() - self.start_time > self.flow_timeout:
                self.end_flow()
                return

            # Update flow information based on the direction
            if direction == "forward":
                self.flow_data["forward_packets"] += 1
                self.flow_data["forward_size"] += len(packet)

    def sniff_traffic(self, interface="Ethernet", count=0):
        # Sniff network traffic and call the packet_callback function for each captured packet
        sniff(prn=self.packet_callback, store=0, iface=interface, count=count)

        # Set flow duration after sniffing is complete
        self.flow_data["duration"] = self.calculate_duration()

    def calculate_duration(self):
        if self.start_time:
            end_time = datetime.now()
            duration = end_time - self.start_time
            return duration.total_seconds()
        else:
            return 0

    def calculate_average_size(self):
        if self.flow_data["forward_packets"] > 0:
            self.flow_data["avg_size_forward"] = (
                self.flow_data["forward_size"] / self.flow_data["forward_packets"]
            )
        else:
            self.flow_data["avg_size_forward"] = 0

    def end_flow(self):
        # Called when the flow timeout is reached
        self.calculate_duration()
        self.calculate_average_size()
        print("Flow ended due to timeout.")
        print(f"Flow Duration: {self.flow_data['duration']} seconds")
        print(f"Protocol: {self.flow_data['protocol']}")
        print(f"Destination Port: {self.flow_data['dest_port']}")
        print(f"Total Packets (Forward): {self.flow_data['forward_packets']}")
        print(f"Total Packets (Backward): {self.flow_data['backward_packets']}")
        print(f"Total Size (Forward): {self.flow_data['forward_size']} bytes")
        print(f"Average Size (Forward): {self.flow_data['avg_size_forward']} bytes")
        exit()

# Example usage:
sniffer = Sniffer()
sniffer.sniff_traffic()