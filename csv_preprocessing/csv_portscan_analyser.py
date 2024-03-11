""" 
    csv_portscan_analyser.py: analyses and balances the data on the CSE-CIC-IDS2018 Dataset relative to Portscan attacks

    (NOTE: There might me some redundant code due to the file sizes. Loading one file at the time and then getting rid of variables allows
        to save RAM and the execution not to crash.)

"""

import pandas as pd
from sklearn.utils import resample
import numpy as np

usecols = [ 'Flow Duration', 'Bwd Pkt Len Max', 'Bwd Pkt Len Min', 'Bwd Pkt Len Mean', 'Bwd Pkt Len Std', 'Flow IAT Mean', 
'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Tot', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 
'Fwd IAT Min', 'Bwd IAT Tot', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags', 
'Fwd Pkts/s', 'Pkt Len Max', 'Pkt Len Mean', 'Pkt Len Std', 'Pkt Len Var', 'FIN Flag Cnt', 
'SYN Flag Cnt', 'PSH Flag Cnt', 'ACK Flag Cnt', 'URG Flag Cnt', 'Pkt Size Avg', 'Bwd Seg Size Avg', 
'Init Fwd Win Byts', 'Init Bwd Win Byts', 'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min', 'Label']

usecols_features_importance = ["Subflow Fwd Bytes", "Pkt Len Std", "Fwd Seg Size Min", "Fwd Pkt Len Max", "Bwd Seg Size Avg", 
           "Fwd Segment Size Avg", "Pkt Len Max", "Fwd Pkt Len Mean", "Flow Bytes/s", "Tot Len of Bwd Pkt", "Bwd Pkts/s", 'Label']

df = pd.read_csv('D:\\Download\\CSECICIDS2018_improved\\Wednesday-28-02-2018.csv', low_memory=True)
majority_class = df[df['Label'] == "BENIGN"]
minority_class = df[df['Label'] == "Infiltration - NMAP Portscan"]
del(df) # Get rid of the variables to save RAM

print("BENIGN: "                                   + str(len(majority_class)) )
print("Infiltration - NMAP Portscan: "             + str(len(minority_class)) )

# Undersample the majority class
undersampled_majority = resample(majority_class,
                                 replace=False,  # Set to True if you want to sample with replacement
                                 n_samples=len(minority_class),  # Match the number of samples in the minority classes
                                 random_state=42)  # Set a random state for reproducibility

# Combine the undersampled majority class with the original minority class
undersampled_df = pd.concat([undersampled_majority, minority_class])

# Shuffle the DataFrame to randomize the order of samples
undersampled_df = undersampled_df.sample(frac=1, random_state=42).reset_index(drop=True)

print("FINAL LENGHT:" + str(len(undersampled_df)))

undersampled_df.replace([np.inf, -np.inf], np.nan, inplace=True)
undersampled_df.dropna(inplace=True)

# Specify the file path where you want to save the CSV file
file_path = 'D:\\dataset_analysed\\portscan_attacks_balanced.csv'

# Write DataFrame to CSV
undersampled_df.to_csv(file_path, index=False) 