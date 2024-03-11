""" 
    csv_DoS_analyser.py: analyses and balances the data on the CSE-CIC-IDS2018 Dataset relative to DoS and DDoS attacks

    (NOTE: There might me some redundant code due to the file sizes. Loading one file at the time and then getting rid of variables allows
        to save RAM and the execution not to crash.)

"""

import pandas as pd
import numpy as np

df = pd.read_csv('D:\\Download\\CSECICIDS2018_improved\\Thursday-15-02-2018.csv') # DoS-GoldenEye & DoS-Slowloris
majority_class = df[df['Label'] == "BENIGN"]
#print("majority before:" + str(len(majority_class)))
minority_class = df[df['Label'] == "DoS Slowloris"]
minority_class2 = df[df['Label'] == "DoS GoldenEye"]
majority_class = majority_class[:len(minority_class + minority_class2)]
#print("majority after:" + str(len(majority_class)))
del(df) # Get rid of the variables to save RAM

df = pd.read_csv('D:\\Download\\CSECICIDS2018_improved\\Friday-16-02-2018.csv') # DoS-Hulk & DoS-SlowHTTPTest
print(df['Label'].unique())
majority_class2 = df[df['Label'] == "BENIGN"]
#print("majority before:" + str(len(majority_class)))
minority_class3 = df[df['Label'] == "DoS Hulk"]
majority_class = pd.concat([majority_class, majority_class2[:len(minority_class3)]])
del(df, majority_class2) # Get rid of the variables to save RAM

df = pd.read_csv('D:\\Download\\CSECICIDS2018_improved\\Tuesday-20-02-2018.csv') # DDoS attacks-LOIC-HTTP & DDoS-LOIC-UDP
majority_class3 = df[df['Label'] == "BENIGN"]
#print("majority before:" + str(len(majority_class)))
minority_class4 = df[df['Label'] == "DDoS-LOIC-HTTP"]
minority_class5 = df[df['Label'] == "DDoS-LOIC-UDP"]
majority_class = pd.concat([majority_class, majority_class3[:len(minority_class4 + minority_class5)]])
del(df, majority_class3) # Get rid of the variables to save RAM

df = pd.read_csv('D:\\Download\\CSECICIDS2018_improved\\Wednesday-21-02-2018.csv') # DDOS-LOIC-UDP & DDOS-HOIC
majority_class4 = df[df['Label'] == "BENIGN"]
#print("majority before:" + str(len(majority_class)))
minority_class5 = pd.concat([minority_class5, df[df['Label'] == "DDoS-LOIC-UDP"]])
minority_class6 = df[df['Label'] == "DDoS-HOIC"]
majority_class = pd.concat([majority_class, majority_class4[:len(minority_class6)]])

del(df, majority_class4) # Get rid of the variables to save RAM

print("_______________________________________________________________________________________________")

print("BENIGN:         "             + str(len(majority_class))  )
print("DoS Slowloris:  "             + str(len(minority_class))  )
print("DoS GoldenEye:  "             + str(len(minority_class2)) )
print("DoS Hulk:       "             + str(len(minority_class3)) )
print("DDoS-LOIC-HTTP: "             + str(len(minority_class4)) )
print("DDoS-LOIC-UDP:  "             + str(len(minority_class5)) )
print("DDoS-HOIC:      "             + str(len(minority_class6)) )

print("_______________________________________________________________________________________________")


# Combine the undersampled majority class with the original minority class
to_csv = pd.concat([majority_class, minority_class, minority_class2, minority_class3, minority_class4, 
                             minority_class5, minority_class6])

to_csv.replace([np.inf, -np.inf], np.nan, inplace=True)
to_csv.dropna(inplace=True)

print("FINAL LENGHT:" + str(len(to_csv)))

# Specify the file path where you want to save the CSV file
file_path = 'D:\\dataset_analysed\\DoS_attacks_balanced.csv'

# Write DataFrame to CSV
to_csv.to_csv(file_path, index=False)