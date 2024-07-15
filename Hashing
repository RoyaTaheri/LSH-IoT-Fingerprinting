import os
import scapy.all as scapy
from nilsimsa import Nilsimsa
from scapy.all import rdpcap, raw
import pandas as pd


def anonymize_ip(packet):
    if scapy.IP in packet:
        packet[scapy.IP].src = "1.1.1.1"
        packet[scapy.IP].dst = "1.1.1.1"
    return packet


def extract_headers_payloads(pcap_file):
    packets = scapy.rdpcap(pcap_file)
    headers = []
    payloads = []

    for packet in packets:

        num_packets = len(packets)
        raw_packet = bytes(packet)
        concatenated_full_packets = b''
        concatenated_full_packets += raw_packet


        if packet.haslayer('Raw'):
            payload = bytes(packet['Raw'])
            #print("P:", payload)
            header = raw_packet[:-len(payload)]
            #print("H:", header)
        else:
            payload = b''
            header = raw_packet

        headers.append(header)
        payloads.append(payload)

        # Concatenate all headers and all payloads
    all_headers = b''.join(headers)
    print(all_headers)
    all_payloads = b''.join(payloads)

    return concatenated_full_packets, all_headers, all_payloads
    # for packet in packets:
    #     anonymized_packet = anonymize_ip(packet)
    #     raw_packet = bytes(anonymized_packet)
    #     print(raw_packet)
    #
    #     first_layer = anonymized_packet.firstlayer()
    #     underlayer = first_layer.underlayer
    #
    #     if underlayer:
    #         header = raw_packet[:underlayer._dport]
    #         payload = raw_packet[underlayer._dport:]
    #         print(payload)
    #         headers.append(header)
    #         payloads.append(payload)
    #     else:
    #         # Handle the case where underlayer is None
    #         headers.append(raw_packet)
    #         payloads.append(b'')
    #
    # return b''.join(headers), b''.join(payloads)


def hash_with_nilsimsa(data):
    nilsimsa = Nilsimsa(data)
    return nilsimsa.hexdigest()


def process_pcap_folder(folder_path):

    results = []
    m=0

    folder_name = os.path.basename(os.path.normpath(folder_path))

    for file_name in os.listdir(folder_path):
        if file_name.endswith(".pcap"):
            m+=1

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


if __name__ == "__main__":
    folder_path = "Aria"  # Path to the folder containing PCAP files
    results = process_pcap_folder(folder_path)

    df = pd.DataFrame(results)
    df.to_csv('pcap_analysis.csv', index=False)
