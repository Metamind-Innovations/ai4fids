import pandas as pd
from os import listdir
from os.path import isfile, join
import json
import os
from tqdm import tqdm 
from helpers import split_packets
import logging
import scapy.all as scapy_all
from ocppflowmeter.ocppflowmeter import websocket_header_properties, unmask
import numpy as np
from scapy.all import sniff, wrpcap

config = None
with open('./config.json') as f:
    config = json.load(f)



def is_websocket(packet):
   # 138 corresponds to \x8a (pong), 137 corresponds to \x89 (ping), 129 corresponds to \x81 (opcode=text), 136 corresponds to \x88 (connection close)
   try:
      if (packet["IP"]["TCP"].payload.load[0] == 138 or packet["IP"]["TCP"].payload.load[0] == 137 or packet["IP"]["TCP"].payload.load[0] == 129 or packet["IP"]["TCP"].payload.load[0] == 136) and \
         (packet["IP"].sport == CSMS_TCP_PORT or packet["IP"].dport == CSMS_TCP_PORT):
         return True
      else:
         return False
   except Exception as e:
      return False


def cicflowmeter_cyberattack_ocpp16_fdi_chargingprofile(unmasked):
    ocpp_message_type = unmasked[0]

    if ocpp_message_type == 2:
        ocpp_operation = unmasked[2]
        if ocpp_operation == "SetChargingProfile":
            for i in unmasked[3]["csChargingProfiles"]["chargingSchedule"]["chargingSchedulePeriod"]:
                if i["limit"] >= 90:
                    return True
    return False


def cicflowmeter_cyberattack_ocpp16_doc_idtag(unmasked):
    ocpp_message_type = unmasked[0]

    if ocpp_message_type == 2:
        ocpp_operation = unmasked[2]
        if ocpp_operation == "RemoteStartTransaction":
            return True
    return False


def analyzePacket(packet):
    malicious = False
    if is_websocket(packet):
        payload = packet["IP"]["TCP"].payload.load
        header_length, payload_length, mask = websocket_header_properties(payload)

        valid = True

        if mask is not None:
            unmasked = unmask(payload[header_length:header_length+payload_length], mask)
            try:
                unmasked = bytearray.decode(unmasked)
            except UnicodeDecodeError:
                #print("Unicode decode error!")
                valid = False
        else:
            unmasked = payload[header_length:]
            try:
                unmasked = unmasked.decode()
            except UnicodeDecodeError:
                #print("Unicode decode error!")
                valid = False
        try:
            unmasked = json.loads(unmasked)
        except Exception as e:
            #print("Exception happened while JSON-decoding OCPP payload.")
            #print(e)
            valid = False
        
        if valid:
            malicious = labelling(unmasked)

    if malicious:
        modified_packet = packet.copy()
        modified_packet["TCP"].flags |= 0x80  # Modify the CWR flag (bitwise OR with 0x80)
        PACKETS_LIST.append(modified_packet)
    else:
        PACKETS_LIST.append(packet)


if __name__ == "__main__":

    global labelling
    global PACKETS_LIST
    global CSMS_TCP_PORT

    CSMS_TCP_PORT = config["OCPPFlowMeter"]["CSMS_TCP_PORT"]

    if len(config["Labelling"]["INPUT_PCAP_FILES"]) == 0:
        pcap_files = [f for f in listdir('./unlabelled-pcap/') if isfile(join('./unlabelled-pcap/', f))]
    else:
        pcap_files = config["Labelling"]["INPUT_CSV_FILES"]

    for pcap_file in pcap_files:

        if 'ChargingProfile' in pcap_file:
            labelling = cicflowmeter_cyberattack_ocpp16_fdi_chargingprofile
        elif 'Denial_of_Charge_IdTag' in pcap_file:
            labelling = cicflowmeter_cyberattack_ocpp16_doc_idtag
        else:
            print("No labelling method for " + pcap_file)
        
        print('Start labelling: ' + pcap_file)

        PACKETS_LIST = []
        sniff(offline="./unlabelled-pcap/" + pcap_file, prn=analyzePacket, store=0)
        wrpcap('./labelled-pcap/' + pcap_file.split('.')[0] + '_pcaplabelled.pcap', PACKETS_LIST)
