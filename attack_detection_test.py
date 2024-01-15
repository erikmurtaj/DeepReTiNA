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

model = joblib.load('random_forest_model_dos.joblib')

# Load the CSV file into a DataFrame
test_data = pd.read_csv('2024-01-15_normal.csv', usecols = usecols)

# Replace infinite values with NaN
test_data.replace([np.inf, -np.inf], np.nan, inplace=True)
test_data.dropna(inplace=True)


scaler = MinMaxScaler()
X_test = scaler.fit_transform(test_data)

y_pred = model.predict(test_data)

print("PREDICTED ATTACKS: " + str((y_pred == 1).sum()))