import argparse
import pyshark
import networkx as nx
import matplotlib.pyplot as plt
from matplotlib.backends.backend_agg import FigureCanvas


def extract_devices_stats_from_pcap(pcap_file):
    # Open the pcap file
    cap = pyshark.FileCapture(pcap_file)
    seq = 0
    eht_cnt = 0
    he_cnt = 0
    vht_cnt = 0
    ht_cnt = 0
    ofdm_a_cnt = 0
    ofdm_g_cnt = 0
    dsss_cnt = 0
    devices = {}
    for packet in cap:
        seq += 1
        # if seq==94: # this one is HE packet, just for sanity
        #  print(seq)
        if packet.highest_layer != '_WS.MALFORMED':
            # try:
            #     print("ltang debug")
            #     print(packet.wlan.fc_type)
            # except AttributeError as e:
            #     print(f"An error occurred: {e}")
            # #     print(packet)
            if packet.wlan.fc_type == '2':
                ta = packet.wlan.ta_resolved
                ra = packet.wlan.ra_resolved

                if ta not in devices:
                    devices[ta] = {
                        'packet_count': 0,
                        '11b_packet_count': 0,
                        '11g_packet_count': 0,
                        '11a_packet_count': 0,
                        'ht_packet_count': 0,
                        'vht_packet_count': 0,
                        'he_packet_count': 0,
                        'be_packet_count': 0,
                        'mcs_rates': {
                            '11b': {},
                            '11g': {},
                            '11a': {},
                            'ht': {},
                            'vht': {},
                            'he': {},
                            'be': {}
                        },
                        'receiver': {}
                    }

                devices[ta]['packet_count'] += 1

                if ra not in devices[ta]['receiver']:
                    devices[ta]['receiver'][ra] = 0
                devices[ta]['receiver'][ra] += 1

                # Determine the packet type
                if packet.radiotap.present_ext == '1' and packet.radiotap.present_eht == '1':
                    devices[ta]['be_packet_count'] += 1
                    mcs = packet.radiotap.eht_user_info_mcs
                    if mcs not in devices[ta]['mcs_rates']['be']:
                        devices[ta]['mcs_rates']['be'][mcs] = 0
                    devices[ta]['mcs_rates']['be'][mcs] += 1

                    # print(f"Packet{seq} is BE type:   MCS {packet.radiotap.eht_user_info_mcs}")
                    eht_cnt += 1
                elif packet.radiotap.present_he == '1':
                    devices[ta]['he_packet_count'] += 1
                    if packet.radiotap.present_mcs == '1':
                        mcs = int(packet.radiotap.he_data_3_data_mcs, 16)
                        if mcs not in devices[ta]['mcs_rates']['he']:
                            devices[ta]['mcs_rates']['he'][mcs] = 0
                        devices[ta]['mcs_rates']['he'][mcs] += 1

                    # print(f"Packet{seq} is HE type:   MCS {packet.radiotap.he_data_3_data_mcs}")
                    he_cnt += 1
                elif packet.wlan_radio.phy == '8' and packet.radiotap.present_vht == '1' and packet.radiotap.present_ext == '0' and packet.radiotap.present_he == '0':
                    devices[ta]['vht_packet_count'] += 1
                    if packet.radiotap.present_mcs == '1':
                        mcs = packet.radiotap.mcs_index
                        if mcs not in devices[ta]['mcs_rates']['vht']:
                            devices[ta]['mcs_rates']['vht'][mcs] = 0
                        devices[ta]['mcs_rates']['vht'][mcs] += 1
                    # else:
                    #     print(f"Packet{seq} is VHT type but MCS info is not present")
                    # print(f"Packet{seq} is VHT type:    MCS {packet.radiotap.mcs_index}")
                    vht_cnt += 1
                elif packet.wlan_radio.phy == '7' and packet.radiotap.present_ext == '0' and packet.radiotap.present_he == '0' and packet.radiotap.present_vht == '0' and packet.radiotap.present_mcs == '1':
                    devices[ta]['ht_packet_count'] += 1
                    mcs = packet.radiotap.mcs_index
                    if mcs not in devices[ta]['mcs_rates']['ht']:
                        devices[ta]['mcs_rates']['ht'][mcs] = 0
                    devices[ta]['mcs_rates']['ht'][mcs] += 1

                    # print(f"Packet{seq} is HT type: MCS {packet.radiotap.mcs_index}")
                    ht_cnt += 1
                elif packet.wlan_radio.phy == '5' and packet.radiotap.present_ext == '0' and packet.radiotap.present_he == '0' and packet.radiotap.present_vht == '0' and packet.radiotap.present_mcs == '0':
                    devices[ta]['11a_packet_count'] += 1
                    mcs = packet.radiotap.datarate + 'Mb/s'
                    if mcs not in devices[ta]['mcs_rates']['11a']:
                        devices[ta]['mcs_rates']['11a'][mcs] = 0
                    devices[ta]['mcs_rates']['11a'][mcs] += 1

                    # print(f"Packet{seq} is 11a type:  {packet.radiotap.datarate}Mb/s")
                    ofdm_a_cnt += 1
                elif packet.wlan_radio.phy == '6' and packet.radiotap.present_ext == '0' and packet.radiotap.present_he == '0' and packet.radiotap.present_vht == '0' and packet.radiotap.present_mcs == '0':
                    devices[ta]['11g_packet_count'] += 1
                    mcs = packet.radiotap.datarate + 'Mb/s'
                    if mcs not in devices[ta]['mcs_rates']['11g']:
                        devices[ta]['mcs_rates']['11g'][mcs] = 0
                    devices[ta]['mcs_rates']['11g'][mcs] += 1

                    # print(f"Packet{seq} is 11g type:  {packet.radiotap.datarate}Mb/s")
                    ofdm_g_cnt += 1
                elif packet.wlan_radio.phy == '4' and packet.radiotap.present_ext == '0' and packet.radiotap.present_he == '0' and packet.radiotap.present_vht == '0' and packet.radiotap.present_mcs == '0':
                    devices[ta]['11b_packet_count'] += 1
                    mcs = packet.radiotap.datarate + 'Mb/s'
                    if mcs not in devices[ta]['mcs_rates']['11b']:
                        devices[ta]['mcs_rates']['11b'][mcs] = 0
                    devices[ta]['mcs_rates']['11b'][mcs] += 1

                    # print(f"Packet{seq} is 11b type:  {packet.radiotap.datarate}Mb/s")
                    dsss_cnt += 1
    return devices


def draw_graph(devices, filterNum):
    G = nx.DiGraph()
    edge_colors = []
    edge_labels = {}

    for mac, stats in devices.items():
        for ra_addr, cnt in stats['receiver'].items():
            if cnt >= filterNum:
                if G.has_edge(mac, ra_addr):
                    G[mac][ra_addr]['count'] += cnt
                else:
                    G.add_edge(mac, ra_addr, count=cnt)

    for src, dst in G.edges:
        if (src, dst) not in edge_labels:
            if (dst, src) in edge_labels:
                edge_colors.append('red')
            else:
                edge_colors.append('blue')
            edge_labels[(src, dst)] = G[src][dst]['count']

    # pos = nx.spring_layout(G, seed=42)
    pos = nx.circular_layout(G)

    nx.draw_networkx_nodes(G, pos, node_color='lightgray')
    nx.draw_networkx_labels(G, pos, font_weight='bold')
    for (src, dst), color in zip(G.edges, edge_colors):
        nx.draw_networkx_edges(G, pos, edgelist=[(src, dst)], edge_color=color, connectionstyle='arc3,rad=0.2',
                               arrowstyle='-|>', arrowsize=10)

    nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels, font_color='black', font_size=10,
                                 verticalalignment='center', label_pos=0.1)

    plt.axis('off')
    plt.show()

def print_summary(devices_stats):
    print(f"Device count: {len(devices_stats)}")
    print("Device statistics:")
    for mac, stats in devices_stats.items():
        print(f"    ======MAC: {mac}    => {stats['packet_count']} data packets======")
        # print(f"    Total Tx Packet count: {stats['packet_count']}")
        for ra_addr, cnt in stats['receiver'].items():
            print(f"    {ra_addr}   <=  {cnt}")

        print(f"    BE packet cnt:      {stats['be_packet_count']}")
        print(f"    HE packet cnt:      {stats['he_packet_count']}")
        print(f"    VHT packet cnt:     {stats['vht_packet_count']}")
        print(f"    HT packet cnt:      {stats['ht_packet_count']}")
        print(f"    11a packet cnt:     {stats['11a_packet_count']}")
        print(f"    11g packet cnt:     {stats['11g_packet_count']}")
        print(f"    11b packet cnt:     {stats['11b_packet_count']}")
        print(f"        MCS per mode:")
        for packet_type, mcs_rates in stats['mcs_rates'].items():
            print(f"        {packet_type}:")
            for mcs, count in mcs_rates.items():
                print(f"            mcs: {mcs},     cnt: {count}")


def process_pcap_file(pcap_file, filter):
    devices_stats = extract_devices_stats_from_pcap(pcap_file)
    print_summary(devices_stats)
    draw_graph(devices_stats, filter)


if __name__ == '__main__':
    # Create the argument parser
    parser = argparse.ArgumentParser(description='Process pcap file')

    # Add the file path parameter
    parser.add_argument('pcap_file', type=str, help='Path to the pcap file')

    # Add the threshold parameter
    parser.add_argument('threshold', type=int, help='Threshold value')

    # Parse the command-line arguments
    args = parser.parse_args()

    # Get the values of the parameters
    pcap_file = args.pcap_file
    threshold = args.threshold

    # Process the pcap file
    process_pcap_file(pcap_file, threshold)