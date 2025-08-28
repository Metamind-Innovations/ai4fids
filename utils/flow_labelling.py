import pandas as pd
from os import listdir, remove
from os.path import isfile, join, exists
import json
from tqdm import tqdm 

import sys
import os.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), os.path.pardir)))

from ocppflowmeter.labelling import *
from knxflowmeter.labelling import *

if __name__ == "__main__":

    global df

    ## Load configuration file
    config = None
    with open('./conf/appflow_config.json') as f:
        config = json.load(f)

    if len(config["Labelling"]["INPUT_CSV_FILES"]) == 0:
        csv_files = [f for f in listdir('./unlabelled-csv/') if isfile(join('./unlabelled-csv/', f))]
    else:
        csv_files = config["Labelling"]["INPUT_CSV_FILES"]

    for csv_file in csv_files:
        
        if 'OcppFlows' in csv_file:
            if 'Heartbeat' in csv_file:
                labelling = ocppflowmeter_cyberattack_ocpp16_dos_flooding_heartbeat
            elif 'ChargingProfile' in csv_file:
                labelling = ocppflowmeter_cyberattack_ocpp16_fdi_chargingprofile
            elif 'Denial_of_Charge_IdTag' in csv_file:
                labelling = ocppflowmeter_cyberattack_ocpp16_doc_idtag
            elif 'UnauthorizedAccess' in csv_file:
                labelling = ocppflowmeter_cyberattack_ocpp16_unauthorized_access
            else:
                print("No labelling method for " + csv_file)
                continue

        elif 'KNXFlows' in csv_file:
            if 'KNXA01' in csv_file:
                labelling = knxflowmeter_cyberattack_knx_fuzzing_mpropread
            elif 'KNXA02' in csv_file:
                labelling = knxflowmeter_cyberattack_knx_reset
            elif 'KNXA03' in csv_file:
                labelling = knxflowmeter_cyberattack_knx_net_scanning
            elif 'KNXA04' in csv_file:
                labelling = knxflowmeter_cyberattack_knx_bus_scanning
            elif 'KNXA05' in csv_file:
                labelling = knxflowmeter_cyberattack_knx_flooding_groupvaluewrite_valid
            elif 'KNXA06' in csv_file:
                labelling = knxflowmeter_cyberattack_knx_flooding_groupvaluewrite_fuzzing

        else: # This means the csv is from CICFlowMeter
            ################## CICFLOWMETER WITH OCPP ATTACKS #############################
            if 'Heartbeat' in csv_file:
                labelling = cicflowmeter_cyberattack_ocpp16_dos_flooding_heartbeat
            elif 'ChargingProfile' in csv_file:
                labelling = cicflowmeter_cyberattack_ocpp16_fdi_chargingprofile
            elif 'Denial_of_Charge_IdTag' in csv_file:
                labelling = cicflowmeter_cyberattack_ocpp16_doc_idtag
            elif 'UnauthorizedAccess' in csv_file and not 'KNXA02' in csv_file:
                labelling = cicflowmeter_cyberattack_ocpp16_unauthorized_access
            ###############################################################################
            ############ CICFLOWMETER WITH KNX ATTACKS ####################################
            elif 'KNXA01' in csv_file:
                labelling = cicflowmeter_cyberattack_knx_fuzzing_mpropread
            elif 'KNXA02' in csv_file:
                labelling = cicflowmeter_cyberattack_knx_reset
            elif 'KNXA03' in csv_file:
                labelling = cicflowmeter_cyberattack_knx_net_scanning
            elif 'KNXA04' in csv_file:
                labelling = cicflowmeter_cyberattack_knx_bus_scanning
            elif 'KNXA05' in csv_file:
                labelling = cicflowmeter_cyberattack_knx_flooding_groupvaluewrite_valid
            elif 'KNXA06' in csv_file:
                labelling = cicflowmeter_cyberattack_knx_flooding_groupvaluewrite_fuzzing
            else:
                print("No labelling method for " + csv_file)
                continue
        
        print('Start labelling: ' + csv_file)

        input_csv = './unlabelled-csv/' + csv_file
        output_csv = "./labelled-csv/" + csv_file.split('.')[0] + "_labelled.csv"
        if exists(output_csv): # Since we are appending to the file, we need to make sure that we are not appending to a file from previous experiment.
            print(output_csv + "already exists. Skipping...")
            continue
            #remove(output_csv)
        
        # Copy the header to the new file
        with open(input_csv, 'r') as fid:
            header_list = fid.readline()

        with open(output_csv, 'w') as fid:
            fid.write(header_list)
        
        df = pd.read_csv('./unlabelled-csv/' + csv_file, chunksize=10000, index_col=False)
        for chunk_df in df:
            for index, row in chunk_df.iterrows():
                labelling(index, config, chunk_df)
            chunk_df.to_csv(output_csv, mode='a', header=False, index=False)
        
