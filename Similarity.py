import pandas as pd
from sklearn.model_selection import KFold
from nilsimsa import Nilsimsa

# Load the CSV file
file_path = 'pcap_analysis.csv'
df = pd.read_csv(file_path)


# Define a function to calculate similarity using Nilsimsa
def calculate_similarity(hash1, hash2):
    return sum(bin(x ^ y).count('1') for x, y in zip(hash1, hash2))


# Define a function to perform k-fold cross-validation and similarity comparison
def perform_kfold_similarity(df, n_splits=5):
    results = []
    kf = KFold(n_splits=n_splits, shuffle=True, random_state=1)

    # Group by device
    devices = df['device_name'].unique()

    for device in devices:
        device_data = df[df['device_name'] == device].reset_index(drop=True)
        X = device_data.index

        for fold, (train_index, test_index) in enumerate(kf.split(X), 1):
            train_data = device_data.iloc[train_index]
            test_data = device_data.iloc[test_index]

            for _, test_row in test_data.iterrows():
                test_full_hash = test_row['full_packet_hash']
                test_header_hash = test_row['header_hash']
                test_payload_hash = test_row['payload_hash']

                avg_similarities = {'full_packet': {}, 'header': {}, 'payload': {}}

                for train_device in devices:
                    train_device_data = df[df['device_name'] == train_device]

                    full_similarities = [
                        calculate_similarity(test_full_hash, train_hash)
                        for train_hash in train_device_data['full_packet_hash']
                    ]
                    header_similarities = [
                        calculate_similarity(test_header_hash, train_hash)
                        for train_hash in train_device_data['header_hash']
                    ]
                    payload_similarities = [
                        calculate_similarity(test_payload_hash, train_hash)
                        for train_hash in train_device_data['payload_hash']
                    ]

                    avg_similarities['full_packet'][train_device] = sum(full_similarities) / len(full_similarities)
                    avg_similarities['header'][train_device] = sum(header_similarities) / len(header_similarities)
                    avg_similarities['payload'][train_device] = sum(payload_similarities) / len(payload_similarities)

                # Determine the predicted label based on maximum average similarity
                predicted_device_full = max(avg_similarities['full_packet'], key=avg_similarities['full_packet'].get)
                predicted_device_header = max(avg_similarities['header'], key=avg_similarities['header'].get)
                predicted_device_payload = max(avg_similarities['payload'], key=avg_similarities['payload'].get)

                results.append({
                    'actual_device': test_row['device_name'],
                    'test_full_packet_hash': test_full_hash,
                    'predicted_device_full_packet': predicted_device_full,
                    'test_header_hash': test_header_hash,
                    'predicted_device_header': predicted_device_header,
                    'test_payload_hash': test_payload_hash,
                    'predicted_device_payload': predicted_device_payload
                })

    return results


# Perform k-fold cross-validation and similarity comparison
results = perform_kfold_similarity(df)

# Convert results to DataFrame and save to CSV
results_df = pd.DataFrame(results)
results_df.to_csv('kfold_similarity_results.csv', index=False)

# Display the first few rows of the results
results_df.head()
