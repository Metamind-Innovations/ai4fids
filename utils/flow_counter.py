import pandas as pd
from tqdm import tqdm 
from os import listdir
from os.path import isfile, join
import json
import sys
import os.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), os.path.pardir)))


INPUT_CSV = [f for f in listdir('./labelled-csv/') if isfile(join('./labelled-csv/', f))]

Malicious_Labels = ['cyberattack_ocpp16_fdi_chargingprofile', 
                    'cyberattack_ocpp16_doc_idtag', 
                    'cyberattack_ocpp16_dos_flooding_heartbeat', 
                    'cyberattack_ocpp16_unauthorized_access',
                    'cyberattack_knx_fuzzing_mpropread',
                    'cyberattack_knx_unauthorized_access',
                    'cyberattack_knx_net_scanning',
                    'cyberattack_knx_bus_scanning',
                    'cyberattack_knx_flooding_valid',
                    'cyberattack_knx_flooding_invalid']

for csv_file in INPUT_CSV:

    Counter_Labels = {
    'cyberattack_ocpp16_fdi_chargingprofile': 0,
    'cyberattack_ocpp16_doc_idtag': 0,
    'cyberattack_ocpp16_dos_flooding_heartbeat': 0, 
    'cyberattack_ocpp16_unauthorized_access': 0
    }

    df = pd.read_csv('./labelled-csv/' + csv_file, chunksize=10000)
    flows_malicious = 0
    total_flows = 0
    flows_normal = 0

    for chunk_df in df:
        chunk_df = chunk_df.reset_index()
        for index, row in chunk_df.iterrows():        
            total_flows += 1
            try:
                if (chunk_df.loc[index, 'Label'] in Malicious_Labels):
                    Counter_Labels[chunk_df.loc[index, 'Label']] += 1
                    flows_malicious += 1
                elif (chunk_df.loc[index, 'Label'] == 'normal'):
                    flows_normal += 1
            except KeyError:
                if (chunk_df.loc[index, 'label'] in Malicious_Labels):
                    flows_malicious += 1
                    Counter_Labels[chunk_df.loc[index, 'label']] += 1
                elif (chunk_df.loc[index, 'label'] == 'normal'):
                    flows_normal += 1    

    print(csv_file)
    print("Total number of flows: " + str(total_flows))
    print("Total number of malicious flows: " + str(flows_malicious))
    print("Total number of normal flows: " + str(flows_normal))
    print("Total number of flows per label: " + json.dumps(Counter_Labels))
    print('====================================================================')

