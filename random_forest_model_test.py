import joblib
import pandas as pd
import numpy as np

from sklearn.metrics import accuracy_score
from sklearn.preprocessing import MinMaxScaler

usecols = [ 'Flow Duration', 'Bwd Pkt Len Max', 'Bwd Pkt Len Min', 'Bwd Pkt Len Mean', 'Bwd Pkt Len Std', 'Flow IAT Mean', 
'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Tot', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 
'Fwd IAT Min', 'Bwd IAT Tot', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags', 
'Fwd Pkts/s', 'Pkt Len Max', 'Pkt Len Mean', 'Pkt Len Std', 'Pkt Len Var', 'FIN Flag Cnt', 
'SYN Flag Cnt', 'PSH Flag Cnt', 'ACK Flag Cnt', 'URG Flag Cnt', 'Pkt Size Avg', 'Bwd Seg Size Avg', 
'Init Fwd Win Byts', 'Init Bwd Win Byts', 'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min', 'Label']

model = joblib.load('random_forest_model_dos.joblib')

# Load the CSV file into a DataFrame
test_data = pd.read_csv('02-15-2018.csv', usecols = usecols)
# Replace infinite values with NaN
test_data.replace([np.inf, -np.inf], np.nan, inplace=True)
test_data.dropna(inplace=True)

# Filter rows where 'Label' is not equal to 'Benign'
#filtered_data = test_data[test_data['Label'] != 'Benign']
dos_attacks = test_data[test_data['Label'] == 'DoS attacks-Slowloris']
#print(len(dos_attacks))
filtered_data = dos_attacks

filtered_data['Label'] = filtered_data['Label'].apply(lambda x: 0 if x == 'Benign' else 1)
print((filtered_data['Label']==1).sum())
print((filtered_data['Label']==0).sum())
print(filtered_data['Label'].unique())

scaler = MinMaxScaler()
# Extract features (X) and target variable (y)
X_test = filtered_data.drop('Label', axis=1)  # Adjust 'target_column' based on your data
X_test = scaler.fit_transform(X_test)
y_test = filtered_data['Label']  # Adjust 'target_column' based on your data

#features = [np.nan if x in [np.inf, -np.inf] else float(x) for x in features]

y_pred = model.predict(X_test)
print((y_pred == 1).sum())

print("PREDICTED: " + str((y_pred == 1).sum()) + " ACTUAL: " + str((y_test == 1).sum()))

# Calculate accuracy
accuracy = accuracy_score(y_test, y_pred)
print(f'Accuracy: {accuracy}')