import os
import pandas as pd
import pyfiglet
import datetime
import json
import uuid
import json
from os import listdir
from os.path import isfile, join
import os
from knxflowmeter.knxflowmeter import knxflowmeter
from threading import Thread
from subprocess import Popen


def print_banner():
    ascii_banner = pyfiglet.figlet_format("AppFlowMeter")
    print(ascii_banner)


def traffic_sniffing(config):
    """
    This function is responsible for sniffing the network traffic, using the timeout and tcpdump software packages.
    """

    print("\n--------------\nNew Network Traffic Capturing\n")
    
    try:
        os.remove('./labelled-pcap/capture_temp.pcap')
    except OSError:
        pass

    time = config["General"]["ONLINE_CAPTURE_DURATION"]
    interface = config["General"]["ONLINE_CAPTURE_INTERFACE"]

    if "ONLINE_CAPTURE_PORTS_BLACKLIST" in config["General"]:
        ports = "\'("
        for i in config["General"]["ONLINE_CAPTURE_PORTS_BLACKLIST"]:
            ports = ports + str(i) + ' or '
        ports = ports[:-4] + ")\'"
        os.system("timeout " + time + " tcpdump -i " + interface + " not port " + ports + " -w ./labelled-pcap/capture_temp.pcap")
        os.system("chmod 777 ./labelled-pcap/capture_temp.pcap")

    elif "ONLINE_CAPTURE_PORTS_WHITELIST" in config["General"]:
        if len(config["General"]["ONLINE_CAPTURE_PORTS_WHITELIST"]) > 0:
            ports = "\'("
            for i in config["General"]["ONLINE_CAPTURE_PORTS_WHITELIST"]:
                ports = ports + str(i) + ' or '
            ports = ports[:-4] + ")\'"
            os.system("timeout " + time + " tcpdump -i " + interface + " port " + ports + " -w ./labelled-pcap/capture_temp.pcap")
            os.system("chmod 777 ./labelled-pcap/capture_temp.pcap")
        else:
            os.system("timeout " + time + " tcpdump -i " + interface + " -w ./labelled-pcap/capture_temp.pcap")
            os.system("chmod 777 ./labelled-pcap/capture_temp.pcap")
    else:
        os.system("timeout " + time + " tcpdump -i " + interface + " -w ./labelled-pcap/capture_temp.pcap")
        os.system("chmod 777 ./labelled-pcap/capture_temp.pcap")

    return 'capture_temp.pcap'


def cicflowmeter(pcap):
    """
    This function is responsible for generating TCP/IP network flows, using CICFlowMeter.
    """

    print("\n--------------\nTCP/TCP Network Flow Statistics Generation\n")

    try:
        os.remove("./labelled-pcap/" + pcap + "_Flow.csv")
    except OSError as error:
        print(error)
        pass

    Popen(["./cfm", "../../labelled-pcap/"+pcap, "../../unlabelled-csv"], cwd="./cicflowmeter/bin").wait()
    os.system("chmod 777 ./unlabelled-csv/" + pcap + "_Flow.csv")
    return "./unlabelled-csv/" + pcap + "_Flow.csv"


def flow_generation(pcap, config):
    if "CICFLOWMETER" in FLOW_MODULES:
        cicflowmeter_flows_CSV_file = cicflowmeter(pcap)

    elif "KNXFLOWMETER" in FLOW_MODULES:
        knxflowmeter_flows_CSV_file = knxflowmeter(pcap, config)

if __name__ == "__main__":
    
    os.system("clear")
    print_banner()

    ## Load configuration file
    config = None
    with open('conf/appflow_config.json') as f:
        config = json.load(f)

    FLOW_MODULES = config["General"]["FLOW_MODULES"]

    if config["General"]["OPERATION_MODE"] == "ONLINE": 

        while True:
            pathPcapFile = traffic_sniffing(config)
            flow_generation(pathPcapFile, config)

    elif config["General"]["OPERATION_MODE"] == "OFFLINE":

        PCAP_FILES = config["General"]["OFFLINE_PCAP_FILES"]
        if not PCAP_FILES:
            PCAP_FILES = [f for f in listdir('./labelled-pcap/') if isfile(join('./labelled-pcap/', f))]

        for pcap in PCAP_FILES:
            flow_generation(pcap, config)
            
