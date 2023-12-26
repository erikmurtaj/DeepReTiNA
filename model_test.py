import pickle
import pandas as pd
import numpy as np

from sklearn.metrics import accuracy_score

usecols = [ 'Flow Duration', 'Bwd Pkt Len Max', 'Bwd Pkt Len Min', 'Bwd Pkt Len Mean', 'Bwd Pkt Len Std', 'Flow IAT Mean', 
'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Tot', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 
'Fwd IAT Min', 'Bwd IAT Tot', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags', 
'Fwd Pkts/s', 'Pkt Len Max', 'Pkt Len Mean', 'Pkt Len Std', 'Pkt Len Var', 'FIN Flag Cnt', 
'SYN Flag Cnt', 'PSH Flag Cnt', 'ACK Flag Cnt', 'URG Flag Cnt', 'Pkt Size Avg', 'Bwd Seg Size Avg', 
'Init Fwd Win Byts', 'Init Bwd Win Byts', 'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min', 'Label']

with open('model.pkl', 'rb') as f:
    model = pickle.load(f)

# Load the CSV file into a DataFrame
test_data = pd.read_csv('03-01-2018.csv', usecols = usecols)
# Replace infinite values with NaN
test_data.replace([np.inf, -np.inf], np.nan, inplace=True)
test_data.dropna(inplace=True)

# Filter rows where 'Label' is not equal to 'Benign'
filtered_data = test_data[test_data['Label'] != 'Benign']

filtered_data['Label'] = filtered_data['Label'].apply(lambda x: 0 if x == 'BENIGN' else 1)

# Extract features (X) and target variable (y) if applicable
X_test = filtered_data.drop('Label', axis=1)  # Adjust 'target_column' based on your data
y_test = filtered_data['Label']  # Adjust 'target_column' based on your data

#features = [np.nan if x in [np.inf, -np.inf] else float(x) for x in features]

y_pred = model.predict(X_test)
converted_results = np.where(y_pred != 'Benign', 1, 0)
count_not_benign = (y_pred != 'Benign').sum()
print("PREDICTED: " + str(count_not_benign) + " ACTUAL: " + str(len(filtered_data)))

# Print the count
print(count_not_benign)


#print(y_pred[y_pred != 'Benign'])

# Calculate accuracy
accuracy = accuracy_score(y_test, converted_results)
print(f'Accuracy: {accuracy}')