""" 
    csv_FTPBruteForce_analyser.py: analyses the data relative to FTP BruteForce attacks.

    (NOTE: Since the FTP BruteForce attacks in the CSE-CIC-IDS2018 Dataset are corrupted, new data has been created. 
        The data has been captured with CICFlowMeter during a simulation of FTP BruteForce attack)

"""

import pandas as pd
import numpy as np

df = pd.read_csv('CICFlowMeter\\data\\daily\\2024-02-26_Flow_1.csv') # Flows captured during a FTP-BruteForce attack 
df2 = pd.read_csv('CICFlowMeter\\data\\daily\\2024-02-26_Flow_2.csv') # Flows captured during a FTP-BruteForce attack 

df = pd.concat([df, df2])

# We know the IP address of the attacker is 192.168.1.10 and the attack was performed on port 21
df.loc[(df['Src IP'] == '192.168.1.10') & (df['Dst Port'] == 21), 'Label'] = 'FTP-BruteForce'
df.loc[df['Label'] == 'No Label', 'Label'] = 'BENIGN'


majority_class = df[df['Label'] == "BENIGN"]
minority_class = df[df['Label'] == "FTP-BruteForce"]

print("_______________________________________________________________________________________________")

print("BENIGN:         "             + str(len(majority_class))  )
print("FTP-BruteForce:  "            + str(len(minority_class))  )

print("_______________________________________________________________________________________________")


# Combine the undersampled majority class with the original minority class
to_csv = pd.concat([majority_class, minority_class])

to_csv.replace([np.inf, -np.inf], np.nan, inplace=True)
to_csv.dropna(inplace=True)

print("FINAL LENGHT:" + str(len(to_csv)))

# Specify the file path where you want to save the CSV file
file_path = 'D:\\dataset_analysed\\FTPBruteForce_attacks_balanced.csv'

# Write DataFrame to CSV
to_csv.to_csv(file_path, index=False)