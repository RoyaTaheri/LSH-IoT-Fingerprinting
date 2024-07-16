import os
import scapy.all as scapy
from nilsimsa import Nilsimsa
from scapy.all import rdpcap, raw
import pandas as pd
from sklearn.model_selection import KFold



def anonymize_ip(packet):
    if scapy.IP in packet:
        packet[scapy.IP].src = "1.1.1.1"
        packet[scapy.IP].dst = "1.1.1.1"

    if packet.haslayer('Ether'):
        packet['Ether'].src = "00:11:22:33:44:55"
        packet['Ether'].dst = "00:11:22:33:44:55"

    return packet


def extract_headers_payloads(pcap_file):
    packets = scapy.rdpcap(pcap_file)
    headers = []
    payloads = []

    for packet in packets:
        raw_packet = bytes(packet)
        concatenated_full_packets = b''
        concatenated_full_packets += raw_packet

        if packet.haslayer('Raw'):
            payload = bytes(packet['Raw'])
            header = raw_packet[:-len(payload)]
        else:
            payload = b''
            header = raw_packet

        headers.append(header)
        payloads.append(payload)

    all_headers = b''.join(headers)
    all_payloads = b''.join(payloads)

    return concatenated_full_packets, all_headers, all_payloads


def hash_with_nilsimsa(data):
    nilsimsa = Nilsimsa(data)
    return nilsimsa.hexdigest()


def process_pcap_folder(folder_path):
    results = []
    m = 0

    folder_name = os.path.basename(os.path.normpath(folder_path))

    for file_name in os.listdir(folder_path):
        if file_name.endswith(".pcap"):
            m += 1

    for file_name in os.listdir(folder_path):
        if file_name.endswith(".pcap"):
            print(file_name)
            file_path = os.path.join(folder_path, file_name)
            full, headers, payloads = extract_headers_payloads(file_path)
            headers_hash = hash_with_nilsimsa(headers)
            payloads_hash = hash_with_nilsimsa(payloads)
            full_hash = hash_with_nilsimsa(full)

            print(f"File: {file_name}")
            print(f"Headers Hash: {headers_hash}")
            print(f"Payloads Hash: {payloads_hash}")
            print()

            results.append({
                'device_name': folder_name,
                'measurement': m,
                'full_packet_hash': full_hash,
                'header_hash': headers_hash,
                'payload_hash': payloads_hash
            })

    return results


def process_multiple_folders(folders_list):
    all_results = []

    for folder_path in folders_list:
        results = process_pcap_folder(folder_path)
        all_results.extend(results)

    return all_results


kf = KFold(n_splits=5, shuffle=True, random_state=1)


if __name__ == "__main__":
    folders_list = ["Aria", "D-LinkCam", "D-LinkDayCam", "D-LinkDoorSensor", "D-LinkHomeHub", "D-LinkSensor", "D-LinkSiren",
                    "D-LinkSwitch", "D-LinkWaterSensor", "EdimaxPlug1101W", "EdimaxPlug2101W", "EdnetCam1", "EdnetCam2", "EdnetGateway",
                    "HomeMaticPlug", "HueBridge", "HueSwitch", "iKettle2", "Lightify", "MAXGateway", "SmarterCoffee", "TP-LinkPlugHS100",
                    "TP-LinkPlugHS110", "WeMoInsightSwitch", "WeMoLink", "WeMoSwitch", "Withings"]  # List your folders here
    results = process_multiple_folders(folders_list)

    df = pd.DataFrame(results)
    df.to_csv('pcap_analysis.csv', index=False)
