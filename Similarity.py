import pandas as pd
from sklearn.model_selection import KFold
from nilsimsa import compare_digests
from sklearn.metrics import precision_score, recall_score, f1_score

# Load the CSV file
file_path = 'pcap_analysis.csv'
df = pd.read_csv(file_path)

device_names = df['device_name'].unique()
device_labels = {device: f'D{i+1}' for i, device in enumerate(device_names)}
df['device_label'] = df['device_name'].map(device_labels)

# Define a function to calculate similarity using compare_digests
def calculate_similarity(hash1, hash2):
    score = compare_digests(hash1, hash2)
    return score


def perform_kfold_similarity(df, hash_type, n_splits=5):
    kf = KFold(n_splits=n_splits, shuffle=True, random_state=1) # Creates a KFold object from scikit-learn with the specified number of splits.
    results = []

    for fold, (train_indices, test_indices) in enumerate(kf.split(df), 1):
        for device in df['device_name'].unique():
            device_data = df[df['device_name'] == device].reset_index(drop=True) # Filters the DataFrame to include only rows corresponding to the current device

            # Split the device data into train and test sets for the current fold
            device_train_indices, device_test_indices = next(kf.split(device_data))  # Splits the device-specific data into training and testing sets for the current fold.
            train_data = device_data.iloc[device_train_indices] # Selects the training data using the indices obtained.
            test_data = device_data.iloc[device_test_indices]   # Selects the testing data using the indices obtained.

            for _, test_row in test_data.iterrows():
                test_hash = test_row[f'{hash_type}_hash']  # Extracts the hash value of the test row based on the specified hash type.

                avg_similarities = {}
                for train_device in df['device_name'].unique():
                    train_device_data = df[df['device_name'] == train_device]

                    # Calculates the similarity between the test hash and each hash in the training device data, storing the results in a list.
                    similarities = [
                        calculate_similarity(test_hash, train_hash)
                        for train_hash in train_device_data[f'{hash_type}_hash']
                    ]

                    avg_similarities[train_device] = sum(similarities) / len(similarities)

                predicted_device = max(avg_similarities, key=avg_similarities.get)

                result_row = {
                    'device_label': device_labels[test_row['device_name']],
                    'fold': fold,
                    'test_hash': test_hash,
                    'actual_device': test_row['device_name'],
                    'predicted_device': predicted_device

                }

                results.append(result_row)

    return results

# Perform k-fold cross-validation and similarity comparison for each hash type
full_packet_results = perform_kfold_similarity(df, 'full_packet')
header_results = perform_kfold_similarity(df, 'header')
payload_results = perform_kfold_similarity(df, 'payload')


# Save results to CSV
def save_results_to_csv(results, filename):
    results_df = pd.DataFrame(results)
    results_df.to_csv(filename, index=False)


# Save results to CSV
save_results_to_csv(full_packet_results, 'full_packet_similarity_results.csv')
save_results_to_csv(header_results, 'header_similarity_results.csv')
save_results_to_csv(payload_results, 'payload_similarity_results.csv')


def calculate_metrics(results_df):
    y_true = results_df['actual_device']
    y_pred = results_df['predicted_device']
    precision = precision_score(y_true, y_pred, average='weighted', zero_division=1)
    recall = recall_score(y_true, y_pred, average='weighted', zero_division=1)
    f1 = f1_score(y_true, y_pred, average='weighted', zero_division=1)
    return precision, recall, f1


# Display the first few rows of each result
full_packet_results_df = pd.read_csv('full_packet_similarity_results.csv')
header_results_df = pd.read_csv('header_similarity_results.csv')
payload_results_df = pd.read_csv('payload_similarity_results.csv')

print("Full Packet Similarity Results:")
print(full_packet_results_df.head())
print("\nHeader Similarity Results:")
print(header_results_df.head())
print("\nPayload Similarity Results:")
print(payload_results_df.head())

full_packet_precision, full_packet_recall, full_packet_f1 = calculate_metrics(full_packet_results_df)
header_precision, header_recall, header_f1 = calculate_metrics(header_results_df)
payload_precision, payload_recall, payload_f1 = calculate_metrics(payload_results_df)

# Print the metrics
print("Full Packet Similarity Metrics:")
print(f"Precision: {full_packet_precision}, Recall: {full_packet_recall}, F1 Score: {full_packet_f1}")
print("\nHeader Similarity Metrics:")
print(f"Precision: {header_precision}, Recall: {header_recall}, F1 Score: {header_f1}")
print("\nPayload Similarity Metrics:")
print(f"Precision: {payload_precision}, Recall: {payload_recall}, F1 Score: {payload_f1}")
