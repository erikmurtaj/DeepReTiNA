import pickle
import joblib
import pandas as pd
import numpy as np

from sklearn.preprocessing import MinMaxScaler

usecols = [ 'Flow Duration', 'Bwd Pkt Len Max', 'Bwd Pkt Len Min', 'Bwd Pkt Len Mean', 'Bwd Pkt Len Std', 'Flow IAT Mean', 
'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Tot', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 
'Fwd IAT Min', 'Bwd IAT Tot', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags', 
'Fwd Pkts/s', 'Pkt Len Max', 'Pkt Len Mean', 'Pkt Len Std', 'Pkt Len Var', 'FIN Flag Cnt', 
'SYN Flag Cnt', 'PSH Flag Cnt', 'ACK Flag Cnt', 'URG Flag Cnt', 'Pkt Size Avg', 'Bwd Seg Size Avg', 
'Init Fwd Win Byts', 'Init Bwd Win Byts', 'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min']

usecols2 = ['Flow Duration', 'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean', 'Bwd Packet Length Std', 'Flow IAT Mean', 'Flow IAT Std', 
'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std', 
'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags', 'Fwd Packets/s', 'Packet Length Max', 'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance', 
'FIN Flag Count', 'SYN Flag Count', 'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count', 'Average Packet Size', 'Bwd Segment Size Avg', 'FWD Init Win Bytes', 
'Bwd Init Win Bytes', 'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min', 'Label']

#usecols  = ['flow_duration', 'bwd_pkt_len_max', 'bwd_pkt_len_min', 'bwd_pkt_len_mean', 'bwd_pkt_len_std', 'flow_iat_mean',
#                        'flow_iat_std', 'flow_iat_max', 'flow_iat_min', 'fwd_iat_tot', 'fwd_iat_mean', 'fwd_iat_std', 'fwd_iat_max',
#                        'fwd_iat_min', 'bwd_iat_tot', 'bwd_iat_mean', 'bwd_iat_std', 'bwd_iat_max', 'bwd_iat_min', 'fwd_psh_flags',
#                        'fwd_pkts_s', 'pkt_len_max', 'pkt_len_mean', 'pkt_len_std', 'pkt_len_var', 'fin_flag_cnt',
#                        'syn_flag_cnt', 'psh_flag_cnt', 'ack_flag_cnt', 'urg_flag_cnt', 'pkt_size_avg', 'bwd_seg_size_avg',
#                        'init_fwd_win_byts', 'init_bwd_win_byts', 'active_min', 'idle_mean', 'idle_std', 'idle_max', 'idle_min']

#model = joblib.load('mlp_model_slowloris_balanced.joblib')
model = pickle.load(open('rf_model_ALL_DoS_no_scaling.pkl', 'rb'))

# Load the CSV file into a DataFrame
test_data = pd.read_csv('2024-01-15_SlowLoris_attack.csv', usecols = usecols)

# Replace infinite values with NaN
test_data.replace([np.inf, -np.inf], np.nan, inplace=True)
test_data.dropna(inplace=True)

# Define the desired column order
desired_order = usecols
# Reorder columns
test_data = test_data[desired_order]

#scaler = MinMaxScaler()
#X_test = scaler.fit_transform(test_data)

y_pred = model.predict(test_data)

print("PREDICTED ATTACKS: " + str((y_pred != "Benign").sum()))
#print("PREDICTED ATTACKS: " + str((y_pred != 0).sum()))

for x in y_pred:
    print(x)