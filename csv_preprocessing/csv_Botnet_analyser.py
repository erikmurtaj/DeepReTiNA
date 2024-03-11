""" 
    csv_Botnet_analyser.py: analyses and balances the data on the CSE-CIC-IDS2018 Dataset relative to Bonet attacks.

"""


import pandas as pd
from sklearn.utils import resample
import numpy as np

df = pd.read_csv('D:\\Download\\CSECICIDS2018_improved\\Friday-02-03-2018.csv')
majority_class = df[df['Label'] == "BENIGN"]
minority_class = df[df['Label'] == "Botnet Ares"]
del(df) # Get rid of the variables to save RAM

print("BENIGN: "                       + str(len(majority_class)) )
print("Botnet Attacks: "               + str(len(minority_class)) )

# Undersample the majority class
undersampled_majority = resample(majority_class,
                                 replace=False,  # Set to True if you want to sample with replacement
                                 n_samples=len(minority_class),  # Match the number of samples in the minority classes
                                 random_state=42)  # Set a random state for reproducibility

# Combine the undersampled majority class with the original minority class
undersampled_df = pd.concat([undersampled_majority, minority_class])

# Shuffle the DataFrame to randomize the order of samples
undersampled_df = undersampled_df.sample(frac=1, random_state=42).reset_index(drop=True)

#undersampled_df['Label'] = undersampled_df['Label'].apply(lambda x: "Benign" if x == 'Benign' else "DoS Attack")

print("FINAL LENGHT:" + str(len(undersampled_df)))

undersampled_df.replace([np.inf, -np.inf], np.nan, inplace=True)
undersampled_df.dropna(inplace=True)

# Specify the file path where you want to save the CSV file
file_path = 'D:\\dataset_analysed\\botnet_attacks_balanced.csv'

# Write DataFrame to CSV
undersampled_df.to_csv(file_path, index=False) 