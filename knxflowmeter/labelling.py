## KNXFLOWMETER Labelling methods

def knxflowmeter_cyberattack_knx_fuzzing_mpropread(index, config, df):
    if df.loc[index, 'ip_src'] in config["Labelling"]["Malicious_IP"] or df.loc[index, 'ip_dst'] in config["Labelling"]["Malicious_IP"]:
        df.loc[index, 'label'] = 'cyberattack_knx_fuzzing_mpropread'
    else:
        df.loc[index, 'label'] = 'normal'


def knxflowmeter_cyberattack_knx_unauthorized_access(index, config, df):
    if df.loc[index, 'ip_src'] in config["Labelling"]["Malicious_IP"] or df.loc[index, 'ip_dst'] in config["Labelling"]["Malicious_IP"]:
        df.loc[index, 'label'] = 'cyberattack_knx_unauthorized_access'
    else:
        df.loc[index, 'label'] = 'normal'


def knxflowmeter_cyberattack_knx_net_scanning(index, config, df):
    if df.loc[index, 'ip_src'] in config["Labelling"]["Malicious_IP"] or df.loc[index, 'ip_dst'] in config["Labelling"]["Malicious_IP"]:
        df.loc[index, 'label'] = 'cyberattack_knx_net_scanning'
    else:
        df.loc[index, 'label'] = 'normal'


def knxflowmeter_cyberattack_knx_bus_scanning(index, config, df):
    if df.loc[index, 'ip_src'] in config["Labelling"]["Malicious_IP"] or df.loc[index, 'ip_dst'] in config["Labelling"]["Malicious_IP"]:
        df.loc[index, 'label'] = 'cyberattack_knx_bus_scanning'
    else:
        df.loc[index, 'label'] = 'normal'


def knxflowmeter_cyberattack_knx_flooding_valid(index, config, df):
    if df.loc[index, 'ip_src'] in config["Labelling"]["Malicious_IP"] or df.loc[index, 'ip_dst'] in config["Labelling"]["Malicious_IP"]:
        df.loc[index, 'label'] = 'cyberattack_knx_flooding_valid'
    else:
        df.loc[index, 'label'] = 'normal'


def knxflowmeter_cyberattack_knx_flooding_invalid(index, config, df):
    if df.loc[index, 'ip_src'] in config["Labelling"]["Malicious_IP"] or df.loc[index, 'ip_dst'] in config["Labelling"]["Malicious_IP"]:
        df.loc[index, 'label'] = 'cyberattack_knx_flooding_invalid'
    else:
        df.loc[index, 'label'] = 'normal'

## CICFLOWMETER Labelling methods

def cicflowmeter_cyberattack_knx_fuzzing_mpropread(index, config, df):

    if df.loc[index, 'Dst IP'] in config["Labelling"]["Malicious_IP"] or df.loc[index, 'Src IP'] in config["Labelling"]["Malicious_IP"]:
        df.loc[index, 'Label'] = 'cyberattack_knx_fuzzing_mpropread'
    else:
        df.loc[index, 'Label'] = 'normal'

def cicflowmeter_cyberattack_knx_unauthorized_access(index, config, df):

    if df.loc[index, 'Dst IP'] in config["Labelling"]["Malicious_IP"] or df.loc[index, 'Src IP'] in config["Labelling"]["Malicious_IP"]:
        df.loc[index, 'Label'] = 'cyberattack_knx_unauthorized_access'
    else:
        df.loc[index, 'Label'] = 'normal'

def cicflowmeter_cyberattack_knx_net_scanning(index, config, df):
    if df.loc[index, 'Dst IP'] in config["Labelling"]["Malicious_IP"] or df.loc[index, 'Src IP'] in config["Labelling"]["Malicious_IP"]:
        df.loc[index, 'Label'] = 'cyberattack_knx_net_scanning'
    else:
        df.loc[index, 'Label'] = 'normal'

def cicflowmeter_cyberattack_knx_bus_scanning(index, config, df):
    if df.loc[index, 'Dst IP'] in config["Labelling"]["Malicious_IP"] or df.loc[index, 'Src IP'] in config["Labelling"]["Malicious_IP"]:
        df.loc[index, 'Label'] = 'cyberattack_knx_bus_scanning'
    else:
        df.loc[index, 'Label'] = 'normal'

def cicflowmeter_cyberattack_knx_flooding_valid(index, config, df):
    if df.loc[index, 'Dst IP'] in config["Labelling"]["Malicious_IP"] or df.loc[index, 'Src IP'] in config["Labelling"]["Malicious_IP"]:
        df.loc[index, 'Label'] = 'cyberattack_knx_flooding_valid'
    else:
        df.loc[index, 'Label'] = 'normal'


def cicflowmeter_cyberattack_knx_flooding_invalid(index, config, df):
    if df.loc[index, 'Dst IP'] in config["Labelling"]["Malicious_IP"] or df.loc[index, 'Src IP'] in config["Labelling"]["Malicious_IP"]:
        df.loc[index, 'Label'] = 'cyberattack_knx_flooding_invalid'
    else:
        df.loc[index, 'Label'] = 'normal'
