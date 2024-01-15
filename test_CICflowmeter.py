import subprocess
import time
import pandas as pd

def capture_flows(interface):
    while True:
        subprocess.run(['cicflowmeter', '-i', interface, '-v', '-T', 'csv'], capture_output=True)
        time.sleep(1)

def extract_flow_features(flow_data):
    features = []
    for flow in flow_data:
        flow_features = {
            'Flow Duration': flow.duration,
            'Bwd Pkt Len Max': flow.max_b_pkt_len,
            'Bwd Pkt Len Min': flow.min_b_pkt_len,
            'Bwd Pkt Len Mean': flow.avg_b_pkt_len,
            'Bwd Pkt Len Std': flow.stddev_b_pkt_len,
            'Flow IAT Mean': flow.avg_flow_iat,
            'Flow IAT Std': flow.stddev_flow_iat,
            'Flow IAT Max': flow.max_flow_iat,
            'Flow IAT Min': flow.min_flow_iat,
            'Fwd IAT Tot': flow.total_fwd_iat,
            'Fwd IAT Mean': flow.avg_fwd_iat,
            'Fwd IAT Std': flow.stddev_fwd_iat,
            'Fwd IAT Max': flow.max_fwd_iat,
            'Fwd IAT Min': flow.min_fwd_iat,
            'Bwd IAT Tot': flow.total_bwd_iat,
            'Bwd IAT Mean': flow.avg_bwd_iat,
            'Bwd IAT Std': flow.stddev_bwd_iat,
            'Bwd IAT Max': flow.max_bwd_iat,
            'Bwd IAT Min': flow.min_bwd_iat,
            'Fwd PSH Flags': flow.fwd_psh_flags,
            'Fwd Pkts/s': flow.pkts_per_sec,
            'Pkt Len Max': flow.max_pkt_len,
            'Pkt Len Mean': flow.avg_pkt_len,
            'Pkt Len Std': flow.stddev_pkt_len,
            'Pkt Len Var': flow.var_pkt_len,
            'FIN Flag Cnt': flow.fin_flag_cnt,
            'SYN Flag Cnt': flow.syn_flag_cnt,
            'PSH Flag Cnt': flow.psh_flag_cnt,
            'ACK Flag Cnt': flow.ack_flag_cnt,
            'URG Flag Cnt': flow.urg_flag_cnt,
            'Pkt Size Avg': flow.pkt_size_avg,
            'Bwd Seg Size Avg': flow.bwd_seg_size_avg,
            'Init Fwd Win Byts': flow.init_fwd_win_bytes,
            'Init Bwd Win Byts': flow.init_bwd_win_bytes,
            'Active Min': flow.active_min,
            'Idle Mean': flow.idle_mean,
            'Idle Std': flow.idle_std,
            'Idle Max': flow.idle_max,
            'Idle Min': flow.idle_min
        }
        features.append(flow_features)
    return features

if __name__ == '__main__':
    # Capture flows in real time from the specified interface
    interface = 'Ethernet'
    capture_flows(interface)

    # Process captured flow data and extract features
    flow_data = []
    while True:
        flow_data += [x.strip('\n') for x in subprocess.check_output(['tail', '-n', '10', 'flow.csv']).split('\n') if x != '']
        # Extract features from each flow
        extracted_features = extract_flow_features(flow_data)
        print(extracted_features)
