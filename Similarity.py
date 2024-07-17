import pandas as pd
from sklearn.model_selection import KFold
from nilsimsa import compare_digests

# Load the CSV file
file_path = 'pcap_analysis.csv'
df = pd.read_csv(file_path)


# Define a function to calculate similarity using compare_digests
def calculate_similarity(hash1, hash2):
    # digest_1 = convert_hex_to_ints(hash1)
    # digest_2 = convert_hex_to_ints(hash2)
    score = compare_digests(hash1, hash2)
    return score


# Define a function to perform k-fold cross-validation and similarity comparison for each hash type
def perform_kfold_similarity(df, hash_type, n_splits=5):
    results = []
    kf = KFold(n_splits=n_splits, shuffle=True, random_state=1)

    devices = df['device_name'].unique()

    for device in devices:
        device_data = df[df['device_name'] == device].reset_index(drop=True)
        X = device_data.index

        for fold, (train_index, test_index) in enumerate(kf.split(X), 1):
            train_data = device_data.iloc[train_index]
            test_data = device_data.iloc[test_index]
            # print(f"Fold {fold}:")
            # print(f"  Train: index={train_index}")
            # print(f"  Test:  index={test_index}")

            for _, test_row in test_data.iterrows():
                test_hash = test_row[f'{hash_type}_hash']

                avg_similarities = {}

                for train_device in devices:
                    train_device_data = df[df['device_name'] == train_device]

                    similarities = [
                        calculate_similarity(test_hash, train_hash)
                        for train_hash in train_device_data[f'{hash_type}_hash']
                    ]

                    avg_similarities[train_device] = sum(similarities) / len(similarities)

                predicted_device = max(avg_similarities, key=avg_similarities.get)
                highest_similarity_score = avg_similarities[predicted_device]

                results.append({
                    'actual_device': test_row['device_name'],
                    'test_hash': test_hash,
                    'predicted_device': predicted_device,
                    'similarity_score': highest_similarity_score
                })

    return results


# Perform k-fold cross-validation and similarity comparison for each hash type
full_packet_results = perform_kfold_similarity(df, 'full_packet')
header_results = perform_kfold_similarity(df, 'header')
payload_results = perform_kfold_similarity(df, 'payload')

# Convert results to DataFrames and save to CSV
full_packet_results_df = pd.DataFrame(full_packet_results)
header_results_df = pd.DataFrame(header_results)
payload_results_df = pd.DataFrame(payload_results)

full_packet_results_df.to_csv('full_packet_similarity_results.csv', index=False)
header_results_df.to_csv('header_similarity_results.csv', index=False)
payload_results_df.to_csv('payload_similarity_results.csv', index=False)

# Display the first few rows of each result
print("Full Packet Similarity Results:")
print(full_packet_results_df.head())
print("\nHeader Similarity Results:")
print(header_results_df.head())
print("\nPayload Similarity Results:")
print(payload_results_df.head())
