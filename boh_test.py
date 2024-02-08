from telnetlib import IP
import threading
import time
import numpy as np
from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict
from statistics import mean, stdev, variance
import joblib
from sklearn.preprocessing import MinMaxScaler

def analyze_flow(flow):
    timestamps = [pkt.time for pkt in flow]

    # Calculate Flow Duration
    flow_duration = timestamps[-1] - timestamps[0]

    # Calculate Flow IATs (Inter-Arrival Times)
    flow_iats = [timestamps[i] - timestamps[i - 1] for i in range(1, len(timestamps))]

    # Calculate Flow IAT Mean if there is more than one packet in the flow
    flow_iat_mean = mean(flow_iats) if len(flow_iats) > 1 else 0

    # Calculate additional features
    fwd_packet_lengths = [pkt.payload.len for pkt in flow if pkt.haslayer(IP) and pkt[IP].src == flow[0][IP].src]
    bwd_packet_lengths = [pkt.payload.len for pkt in flow if pkt.haslayer(IP) and pkt[IP].dst == flow[0][IP].src]
    
    # Additional attributes
    flow_iat_std = stdev(flow_iats) if len(flow_iats) > 1 else 0
    fwd_iat_mean = mean(flow_iats) if flow_iats else 0
    fwd_iat_std = stdev(flow_iats) if len(flow_iats) > 1 else 0
    fwd_iat_max = max(flow_iats) if flow_iats else 0
    fwd_iat_min = min(flow_iats) if flow_iats else 0
    bwd_iat_tot = sum(flow_iats) if flow_iats else 0
    bwd_iat_mean = mean(flow_iats) if flow_iats else 0
    bwd_iat_std = stdev(flow_iats) if len(flow_iats) > 1 else 0
    bwd_iat_max = max(flow_iats) if flow_iats else 0
    bwd_iat_min = min(flow_iats) if flow_iats else 0

    fwd_psh_flags = sum(1 for pkt in flow if pkt.haslayer(TCP) and pkt[TCP].flags & 0x08)  # Check if PSH flag is set
    pkt_len_max = max(fwd_packet_lengths + bwd_packet_lengths) if fwd_packet_lengths or bwd_packet_lengths else 0
    pkt_len_mean = mean(fwd_packet_lengths + bwd_packet_lengths) if fwd_packet_lengths or bwd_packet_lengths else 0
    pkt_len_std = stdev(fwd_packet_lengths + bwd_packet_lengths) if len(fwd_packet_lengths + bwd_packet_lengths) > 1 else 0
    pkt_len_var = variance(fwd_packet_lengths + bwd_packet_lengths) if len(fwd_packet_lengths + bwd_packet_lengths) > 1 else 0
    fin_flag_cnt = sum(1 for pkt in flow if pkt.haslayer(TCP) and pkt[TCP].flags & 0x01)  # Check if FIN flag is set
    syn_flag_cnt = sum(1 for pkt in flow if pkt.haslayer(TCP) and pkt[TCP].flags & 0x02)  # Check if SYN flag is set
    psh_flag_cnt = sum(1 for pkt in flow if pkt.haslayer(TCP) and pkt[TCP].flags & 0x08)  # Check if PSH flag is set
    ack_flag_cnt = sum(1 for pkt in flow if pkt.haslayer(TCP) and pkt[TCP].flags & 0x10)  # Check if ACK flag is set
    urg_flag_cnt = sum(1 for pkt in flow if pkt.haslayer(TCP) and pkt[TCP].flags & 0x20)  # Check if URG flag is set
    pkt_size_avg = mean(fwd_packet_lengths + bwd_packet_lengths) if fwd_packet_lengths or bwd_packet_lengths else 0

    # Calculate additional attributes
    bwd_seg_size_avg = mean([pkt[TCP].window for pkt in flow if pkt.haslayer(TCP) and pkt[TCP].window]) if any(pkt.haslayer(TCP) and pkt[TCP].window for pkt in flow) else 0
    init_fwd_win_byts = flow[0][TCP].window if flow and flow[0].haslayer(TCP) and flow[0][TCP].window else 0
    init_bwd_win_byts = flow[0][TCP].window if flow and flow[0].haslayer(TCP) and flow[0][TCP].window else 0
    active_min = min(timestamps) if timestamps else 0
    idle_mean = mean([timestamps[i] - timestamps[i - 1] for i in range(1, len(timestamps))]) if len(timestamps) > 1 else 0
    idle_std = stdev([timestamps[i] - timestamps[i - 1] for i in range(1, len(timestamps))]) if len(timestamps) > 2 else 0
    idle_max = max(timestamps) if timestamps else 0
    idle_min = min(timestamps) if timestamps else 0
    
    attributes = {
        'Flow Duration': flow_duration,
        'Bwd Pkt Len Max': max(bwd_packet_lengths) if bwd_packet_lengths else 0,
        'Bwd Pkt Len Min': min(bwd_packet_lengths) if bwd_packet_lengths else 0,
        'Bwd Pkt Len Mean': mean(bwd_packet_lengths) if bwd_packet_lengths else 0,
        'Bwd Pkt Len Std': stdev(bwd_packet_lengths) if len(bwd_packet_lengths) > 1 else 0,
        'Tot Bwd Pkts': len(bwd_packet_lengths),
        'Fwd IAT Tot': sum(flow_iats),
        'Fwd Pkts/s': len(fwd_packet_lengths) / flow_duration if flow_duration > 0 else 0,
        'TotLen Fwd Pkts': sum(fwd_packet_lengths),
        'Flow IAT Mean': flow_iat_mean,
        'Flow IAT Max': max(flow_iats) if flow_iats else 0,
        'Flow IAT Min': min(flow_iats) if flow_iats else 0,
        'Fwd Pkt Len Std': stdev(fwd_packet_lengths) if len(fwd_packet_lengths) > 1 else 0,
        'Fwd Pkt Len Max': max(fwd_packet_lengths) if fwd_packet_lengths else 0,
        'Fwd Pkt Len Min': min(fwd_packet_lengths) if fwd_packet_lengths else 0,
        'TotLen Bwd Pkts': sum(bwd_packet_lengths),
        'Tot Fwd Pkts': len(fwd_packet_lengths),
        'Flow IAT Std': flow_iat_std,
        'Fwd IAT Mean': fwd_iat_mean,
        'Fwd IAT Std': fwd_iat_std,
        'Fwd IAT Max': fwd_iat_max,
        'Fwd IAT Min': fwd_iat_min,
        'Bwd IAT Tot': bwd_iat_tot,
        'Bwd IAT Mean': bwd_iat_mean,
        'Bwd IAT Std': bwd_iat_std,
        'Bwd IAT Max': bwd_iat_max,
        'Bwd IAT Min': bwd_iat_min,
        'Fwd PSH Flags': fwd_psh_flags,
        'Pkt Len Max': pkt_len_max,
        'Pkt Len Mean': pkt_len_mean,
        'Pkt Len Std': pkt_len_std,
        'Pkt Len Var': pkt_len_var,
        'FIN Flag Cnt': fin_flag_cnt,
        'SYN Flag Cnt': syn_flag_cnt,
        'PSH Flag Cnt': psh_flag_cnt,
        'ACK Flag Cnt': ack_flag_cnt,
        'URG Flag Cnt': urg_flag_cnt,
        'Pkt Size Avg': pkt_size_avg,
        'Bwd Seg Size Avg': bwd_seg_size_avg,
        'Init Fwd Win Byts': init_fwd_win_byts,
        'Init Bwd Win Byts': init_bwd_win_byts,
        'Active Min': active_min,
        'Idle Mean': idle_mean,
        'Idle Std': idle_std,
        'Idle Max': idle_max,
        'Idle Min': idle_min
    }
    return attributes

def main():

    model = joblib.load('random_forest_model_ALL_DoS_v2.joblib')

    flows = defaultdict(list)
    lock = threading.Lock()

    def packet_callback(packet):
        if IP in packet:
            flow_key = tuple(sorted([
                str(packet[IP].src),
                str(packet[IP].dst),
                str(packet[IP].sport) if hasattr(packet[IP], 'sport') else 'N/A',  # Check if 'sport' attribute exists
                str(packet[IP].dport) if hasattr(packet[IP], 'dport') else 'N/A'   # Check if 'dport' attribute exists
            ]))
            flows[flow_key].append(packet)

    #try:
    #    sniff(prn=packet_callback, store=0, count=10000)  # Adjust count or filter based on your needs
    #except KeyboardInterrupt:
    #    pass

    def flow_classification(flow_key, flow):

        selected_attributes  = ['Flow Duration', 'Bwd Pkt Len Max', 'Bwd Pkt Len Min', 'Bwd Pkt Len Mean', 'Bwd Pkt Len Std', 'Flow IAT Mean',
                                'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Tot', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max',
                                'Fwd IAT Min', 'Bwd IAT Tot', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags',
                                'Fwd Pkts/s', 'Pkt Len Max', 'Pkt Len Mean', 'Pkt Len Std', 'Pkt Len Var', 'FIN Flag Cnt',
                                'SYN Flag Cnt', 'PSH Flag Cnt', 'ACK Flag Cnt', 'URG Flag Cnt', 'Pkt Size Avg', 'Bwd Seg Size Avg',
                                'Init Fwd Win Byts', 'Init Bwd Win Byts', 'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min']
        
        selected_attributes_values = {attr: flow[attr] for attr in selected_attributes}
        to_array = np.array(list(selected_attributes_values.values()))

        # Reshape the data array
        X_test = to_array.reshape(1, -1)

        #scaler = MinMaxScaler()
        #X_test = scaler.fit_transform(X_test)
        y_pred = model.predict(X_test)

        print(str(flow_key) + " ==> " + str(y_pred))

    def packet_consumer():
        while True:
            with lock:
                if flows:
                    flow_key, flow = flows.popitem()
                    flow_attributes = analyze_flow(flow)
                    flow_classification(flow_key, flow_attributes)
            time.sleep(0.1)

    def packet_producer():
        try:
            sniff(prn=packet_callback, store=0, count=0)  # Adjust count or filter based on your needs
        except KeyboardInterrupt:
            pass

    # Start consumer thread
    consumer_thread = threading.Thread(target=packet_consumer)
    consumer_thread.start()

    # Start producer thread
    producer_thread = threading.Thread(target=packet_producer)
    producer_thread.start()

    # Wait for both threads to finish
    producer_thread.join()
    consumer_thread.join()

"""     for flow_key, flow in flows.items():
        flow_attributes = analyze_flow(flow)
        selected_attributes  = ['Bwd Pkt Len Std', 'Tot Bwd Pkts', 'Fwd IAT Tot', 'Fwd Pkts/s', 'TotLen Fwd Pkts', 'Flow IAT Max', 'Fwd Pkt Len Std', 
                    'Fwd Pkt Len Max', 'Flow IAT Min', 'Fwd Pkt Len Min', 'Bwd Pkt Len Mean', 'TotLen Bwd Pkts', 'Tot Fwd Pkts']
        selected_attributes_values = {attr: flow_attributes[attr] for attr in selected_attributes}
        #print(f"Flow {flow_key}: {selected_attributes_values}")
        # Convert the dictionary values into a 1D array using numpy
        to_array = np.array(list(selected_attributes_values.values()))
        # Reshape the data array
        X_test = to_array.reshape(1, -1)

        scaler = MinMaxScaler()
        X_test = scaler.fit_transform(X_test)
        y_pred = model.predict(X_test)

        print(flow_key + " ==> " + y_pred) """

if __name__ == "__main__":
    main()



