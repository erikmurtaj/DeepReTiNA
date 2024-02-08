import pickle
import pandas as pd
from sklearn.utils import resample
import numpy as np

""" usecols = ['Flow Duration', 'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean', 'Bwd Packet Length Std', 'Flow IAT Mean', 'Flow IAT Std', 
'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std', 
'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags', 'Fwd Packets/s', 'Packet Length Max', 'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance', 
'FIN Flag Count', 'SYN Flag Count', 'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count', 'Average Packet Size', 'Bwd Segment Size Avg', 'FWD Init Win Bytes', 
'Bwd Init Win Bytes', 'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min', 'Label'] """

usecols = [ 'Flow Duration', 'Bwd Pkt Len Max', 'Bwd Pkt Len Min', 'Bwd Pkt Len Mean', 'Bwd Pkt Len Std', 'Flow IAT Mean', 
'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Tot', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 
'Fwd IAT Min', 'Bwd IAT Tot', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags', 
'Fwd Pkts/s', 'Pkt Len Max', 'Pkt Len Mean', 'Pkt Len Std', 'Pkt Len Var', 'FIN Flag Cnt', 
'SYN Flag Cnt', 'PSH Flag Cnt', 'ACK Flag Cnt', 'URG Flag Cnt', 'Pkt Size Avg', 'Bwd Seg Size Avg', 
'Init Fwd Win Byts', 'Init Bwd Win Byts', 'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min', 'Label']

df = pd.read_csv('D:\\Download\\Thursday-15-02-2018.csv',  usecols = usecols) # DoS-GoldenEye & DoS-Slowloris

# Combine the two categories into one
df.loc[df['Label'] == "DoS Slowloris - Attempted", 'Label'] = "DoS Slowloris"

majority_class = df[df['Label'] == "BENIGN"]
minority_class = df[df['Label'] == "DoS Slowloris"]

print("BENIGN: "                    + str(len(majority_class)) )
print("DoS Slowloris: "             + str(len(minority_class)) )

del(df) # Get rid of the variables to save RAM

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
file_path = 'slowloris_attacks_balanced.csv'

# Write DataFrame to CSV
#undersampled_df.to_csv(file_path, index=False) 

from sklearn.preprocessing import MinMaxScaler
import numpy as np

undersampled_df.replace([np.inf, -np.inf], np.nan, inplace=True)
undersampled_df.dropna(inplace=True)

features = undersampled_df.columns.drop(["Label"])
print(features)

scaler = MinMaxScaler()

X = undersampled_df[features]
#X = scaler.fit_transform(X)
y = undersampled_df["Label"]

from sklearn.metrics import accuracy_score, classification_report
from sklearn.ensemble import RandomForestClassifier

from sklearn.model_selection import train_test_split

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size = 0.20, random_state=42)

rf_classifier = RandomForestClassifier(max_depth=16, n_estimators=20)

rf_classifier.fit(X_train, y_train)
y_pred = rf_classifier.predict(X_test)

# Evaluate the model
accuracy = accuracy_score(y_test, y_pred)
print(f'Accuracy: {accuracy:.2f}')

# Display classification report
print(classification_report(y_test, y_pred))

# Export the model using pickle
with open("rf_classifier_slowloris_v2.pkl", 'wb') as file:
    pickle.dump(rf_classifier, file)