""" 
    csv_BruteForce_analyser.py: analyses and balances the data on the CSE-CIC-IDS2018 Dataset relative to BruteForce attacks

    (NOTE: There might me some redundant code due to the file sizes. Loading one file at the time and then getting rid of variables allows
        to save RAM and the execution not to crash.)

"""

import pandas as pd
import numpy as np

df = pd.read_csv('D:\\Download\\CSECICIDS2018_improved\\Wednesday-14-02-2018.csv') # SSH-BruteForce 
majority_class = df[df['Label'] == "BENIGN"]

minority_class = df[df['Label'] == "SSH-BruteForce"]
majority_class = majority_class[:len(minority_class)]

del(df) # Get rid of the variables to save RAM

df = pd.read_csv('D:\\Download\\CSECICIDS2018_improved\\Thursday-22-02-2018.csv') # Web Attack - SQL & Web Attack - XSS & Web Attack - Brute Force
majority_class2 = df[df['Label'] == "BENIGN"]

minority_class2 = df[df['Label'] == "Web Attack - SQL"]
minority_class3 = df[df['Label'] == "Web Attack - XSS"]
minority_class4 = df[df['Label'] == "Web Attack - Brute Force"]
majority_class = pd.concat([majority_class, majority_class2[:len(minority_class2 + minority_class3 + minority_class4)]])
del(df, majority_class2) # Get rid of the variables to save RAM

df = pd.read_csv('D:\\Download\\CSECICIDS2018_improved\\Friday-23-02-2018.csv') # Web Attack - SQL & Web Attack - XSS & Web Attack - Brute Force
#majority_class3 = df[df['Label'] == "BENIGN"]

minority_class5 = df[df['Label'] == "Web Attack - SQL"]
minority_class6 = df[df['Label'] == "Web Attack - XSS"]
minority_class7 = df[df['Label'] == "Web Attack - Brute Force"]

minority_class2 = pd.concat([minority_class2, minority_class5])
minority_class3 = pd.concat([minority_class2, minority_class6])
minority_class4 = pd.concat([minority_class3, minority_class7])
#majority_class = pd.concat([majority_class, majority_class3[:len(minority_class4 + minority_class5)]])
del(df, minority_class5, minority_class6, minority_class7) # Get rid of the variables to save RAM


print("_______________________________________________________________________________________________")

print("BENIGN:         "             + str(len(majority_class))  )
print("SSH-BruteForce:  "            + str(len(minority_class))  )
print("Web Attack - SQL:  "          + str(len(minority_class2)) )
print("Web Attack - XSS:       "     + str(len(minority_class3)) )
print("Web Attack - Brute Force: "   + str(len(minority_class4)) )

print("_______________________________________________________________________________________________")


# Combine the undersampled majority class with the original minority class
to_csv = pd.concat([majority_class, minority_class, minority_class2, minority_class3, minority_class4])

to_csv.replace([np.inf, -np.inf], np.nan, inplace=True)
to_csv.dropna(inplace=True)

print("FINAL LENGHT:" + str(len(to_csv)))

# Specify the file path where you want to save the CSV file
file_path = 'D:\\dataset_analysed\\BruteForce_attacks_balanced.csv'

# Write DataFrame to CSV
to_csv.to_csv(file_path, index=False)