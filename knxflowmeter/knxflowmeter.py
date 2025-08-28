import scapy.all as scapy_all
from scapy.utils import EDecimal
from scapy.contrib import knx as scapy_knx
from scapy.layers import inet
import os
import logging
from tqdm import tqdm
logging.basicConfig(level=logging.INFO)
from utils.helpers import split_packets
from utils.helpers import divide
from utils.helpers import BaseFlowProp
import statistics
from decimal import Decimal
from pydantic import ValidationError


class KNXFlowProp(BaseFlowProp):
    flow_id: str = ''
    ip_src: str = ''
    ip_dst: str = ''
    udp_sport: int = 0
    udp_dport: int = 0
    icmp_code_3_count: int = 0
    flow_packets_count: int = 0
    flow_packet_length_max: int = 0
    flow_packet_length_min: int = 0
    flow_packet_length_mean: float = 0
    flow_packet_length_std: float = 0
    flow_packet_length_var: float = 0
    flow_duration: EDecimal = EDecimal(0)
    flow_down_up_ratio: float = 0
    flow_start_timestamp: EDecimal = EDecimal(0)
    flow_end_timestamp: EDecimal = EDecimal(0)
    flow_knxip_count: int = 0
    fw_knxip_count: int = 0
    bw_knxip_count: int = 0
    flow_knxip_down_up_ratio: float = 0
    flow_knxip_pps: float = 0
    fw_knxip_pps: float = 0
    bw_knxip_pps: float = 0
    flow_knxip_bps: float = 0
    fw_knxip_bps: float = 0
    bw_knxip_bps: float = 0
    flow_knxip_status_bad_count: int = 0
    flow_knxip_hpai_disc_count: int = 0
    flow_knxip_hpai_ctrl_count: int = 0
    flow_knxip_hpai_data_count: int = 0
    flow_knxip_cri_count: int = 0
    flow_knxip_dib_count: int = 0
    flow_knxip_crd_count: int = 0
    flow_knxip_comchannel_count: int = 0
    flow_knxip_load_max: int = 0
    flow_knxip_load_min: int = 0
    flow_knxip_load_mean: float = 0
    flow_knxip_load_std: float = 0
    flow_knxip_load_var: float = 0
    fw_knxip_load_max: int = 0
    fw_knxip_load_min: int = 0
    fw_knxip_load_mean: float = 0
    fw_knxip_load_std: float = 0
    fw_knxip_load_var: float = 0
    bw_knxip_load_max: int = 0
    bw_knxip_load_min: int = 0
    bw_knxip_load_mean: float = 0
    bw_knxip_load_std: float = 0
    bw_knxip_load_var: float = 0
    flow_knxip_load_bps: float = 0
    fw_knxip_load_bps: float = 0
    bw_knxip_load_bps: float = 0
    flow_cemi_mcode_lrawreq_count: int = 0
    flow_cemi_mcode_ldatareq_count: int = 0
    flow_cemi_mcode_lpolldatareq_count: int = 0
    flow_cemi_mcode_lpolldatacon_count: int = 0
    flow_cemi_mcode_ldataind_count: int = 0
    flow_cemi_mcode_lbusmonind_count: int = 0
    flow_cemi_mcode_lrawind_count: int = 0
    flow_cemi_mcode_ldatacon_count: int = 0
    flow_cemi_mcode_lrawcon_count: int = 0
    flow_cemi_mcode_mpropinfoind_count: int = 0
    flow_cemi_mcode_mpropreadcon_count: int = 0
    flow_cemi_mcode_mpropreadreq_count: int = 0
    flow_cemi_mcode_mpropwritecon_count: int = 0
    flow_cemi_mcode_mpropwritereq_count: int = 0
    flow_cemi_mcode_mresetcon_count: int = 0
    flow_cemi_mcode_mresetreq_count: int = 0
    flow_cemi_mcode_other_count: int = 0
    flow_cemi_ctrl1_eframe_count: int = 0
    flow_cemi_ctrl1_sframe_count: int = 0
    flow_cemi_ctrl1_repeat_count: int = 0
    flow_cemi_ctrl1_broadcast_count: int = 0
    flow_cemi_ctrl1_prio0_count: int = 0
    flow_cemi_ctrl1_prio1_count: int = 0
    flow_cemi_ctrl1_prio2_count: int = 0
    flow_cemi_ctrl1_prio3_count: int = 0
    flow_cemi_ctrl1_error_count: int = 0
    flow_cemi_ctrl2_hops_mean: float = 0
    flow_cemi_ctrl2_hops_max: int = 0
    flow_cemi_ctrl2_hops_min: int = 0
    flow_cemi_ctrl2_hops_std: float = 0
    flow_cemi_ctrl2_hops_var: float = 0
    flow_cemi_src_count: int = 0
    flow_cemi_dst_count: int = 0
    flow_cemi_mpropread_objType_count: int = 0
    flow_cemi_mpropread_objInstance_count: int = 0
    flow_cemi_mpropread_propId_count: int = 0
    flow_cemi_mpropread_error_count: int = 0
    flow_cemi_tpci_data_count: int = 0
    flow_cemi_tpci_other_count: int = 0
    flow_cemi_apci_groupvalueread_count: int = 0
    flow_cemi_apci_groupvalueresp_count: int = 0
    flow_cemi_apci_groupvaluewrite_count: int = 0
    flow_cemi_apci_indaddwrite_count: int = 0
    flow_cemi_apci_indaddread_count: int = 0
    flow_cemi_apci_indaddresp_count: int = 0
    flow_cemi_apci_restart_count: int = 0
    flow_cemi_apci_esc_count: int = 0
    flow_cemi_apci_other_count: int = 0
    label: str = 'NeedManualLabel'

    class Config:
        arbitrary_types_allowed=True

    def __init__(self):
        super().__init__()


#this will create a list with the rest of the packets that belong to the flow as specified by the first packet
class KNXFlow():
    prop: KNXFlowProp

    #initialize necessary parameters here
    def __init__(self, first_packet):

        super().__init__()

        self.prop = KNXFlowProp()
      
        self.flow_array_packets_all = []   # Keeps all the packets in the flow
        self.flow_array_packets_forward = []  # Keeps all the packets in the forward direction
        self.flow_array_packets_backward = []  # Keeps all the packets in the backwards direction
        
        self.flow_array_packets_knxip_all = []
        self.flow_array_packets_knxip_forward = []
        self.flow_array_packets_knxip_backward = []
        self.flow_array_packets_length = []

        ## Helper variables/arrays to calculate KNX statistics at the end of the flow

        self.flow_array_knxip_comchannel = []
        
        self.flow_array_knxip_load = []
        self.fw_array_knxip_load = []
        self.bw_array_knxip_load = []
        self.flow_array_hops = []

        self.flow_array_cemi_src = []
        self.flow_array_cemi_dst = []
        self.flow_array_cemi_mpropread_objType = []
        self.flow_array_cemi_mpropread_objInstance = []
        self.flow_array_cemi_mpropread_propId = []

        self.initial_stats(first_packet)

        if inet.ICMP in first_packet:
            self.icmp_stats(first_packet)

        if scapy_knx.KNX in first_packet:
        #if first_packet["UDP"].payload.name == "KNXnet/IP":
            self.knx_stats(first_packet, is_forward=True)

        self.pkts_in_flow(first_packet)


    #get list of all flow packets and call the relevant function for each packet
    def pkts_in_flow(self, first_packet):
        self.flow_array_packets_all.append(first_packet)
        self.flow_array_packets_length.append(len(first_packet))
        self.flow_array_packets_forward.append(first_packet)
        is_forward = True

        for packet in packets:
            #FWD
            if "IP" in packet:
                if (packet["IP"].src == self.prop.ip_src) and (packet.sport == self.prop.ip_dst) and (packet != first_packet):
                    self.flow_array_packets_all.append(packet)
                    self.flow_array_packets_length.append(len(packet))
                    self.flow_array_packets_forward.append(packet)
                    self.prop.flow_end_timestamp = packet.time*1000000000
                    is_forward = True

                #BWD
                else:
                    self.flow_array_packets_all.append(packet)
                    self.flow_array_packets_length.append(len(packet))
                    self.flow_array_packets_backward.append(packet)
                    self.prop.flow_end_timestamp = packet.time*1000000000
                    is_forward = False
                
                if inet.ICMP in packet:
                    self.icmp_stats(packet)

                if scapy_knx.KNX in packet:
                    self.flow_array_packets_knxip_all.append(packet)
                    self.knx_stats(first_packet, is_forward)
        
        self.final_stats()
        self.write_flow_to_csv()


    #this function will extract statistics of the Transport layer protocol
    def initial_stats(self, first_packet):
        self.prop.ip_src = first_packet["IP"].src
        self.prop.ip_dst = first_packet["IP"].dst
        self.prop.udp_sport = first_packet["IP"].sport
        self.prop.udp_dport = first_packet["IP"].dport
        self.prop.flow_id = str(self.prop.ip_src)+"-"+str(self.prop.ip_dst)+"-"+str(self.prop.udp_sport)+"-"+str(self.prop.udp_dport)
        self.prop.flow_start_timestamp = first_packet.time*1000000000  #nanoseconds


    def icmp_stats(self, packet):
        if packet["ICMP"].type == 3:
            self.prop.icmp_code_3_count += 1


    def knx_stats(self, packet, is_forward):
        self.prop.flow_knxip_bps += packet["KNX"].total_length
        if is_forward:
            self.flow_array_packets_knxip_forward.append(packet)
            self.prop.fw_knxip_bps += len(packet["KNX"])
        else:
            self.flow_array_packets_knxip_backward.append(packet)
            self.prop.bw_knxip_bps += len(packet["KNX"])

        if hasattr(packet["KNX"].payload, 'status'):  # knx_payload == packet["KNX"].payload
            if packet["KNX"].payload.status != 0:  # 0 means OK
                self.prop.flow_knxip_status_bad_count += 1
        
        if hasattr(packet["KNX"].payload, 'discovery_endpoint'):
            self.prop.flow_knxip_hpai_disc_count += 1
        
        if hasattr(packet["KNX"].payload, 'control_endpoint'):
            self.prop.flow_knxip_hpai_ctrl_count += 1

        if hasattr(packet["KNX"].payload, 'control_endpoint'):
            self.prop.flow_knxip_hpai_ctrl_count += 1

        if hasattr(packet["KNX"].payload, 'data_endpoint'):
            self.prop.flow_knxip_hpai_data_count += 1

        if hasattr(packet["KNX"].payload, 'connection_request_information'):
            self.prop.flow_knxip_cri_count += 1

        if hasattr(packet["KNX"].payload, 'device_info'):
            self.prop.flow_knxip_dib_count += 1

        if hasattr(packet["KNX"].payload, 'connection_response_data_block'):
            self.prop.flow_knxip_crd_count += 1

        if hasattr(packet["KNX"].payload, 'payload'):
            if hasattr(packet["KNX"].payload.payload, 'load'):
                load = int.from_bytes(packet["KNX"].payload.payload.load, 'big')
                self.flow_array_knxip_load.append(load) 
                if is_forward:
                    self.fw_array_knxip_load.append(load) 
                else:
                    self.bw_array_knxip_load.append(load)
        
        if hasattr(packet["KNX"].payload, 'cemi'):
            if packet["KNX"].payload.cemi.message_code == 16:
                self.prop.flow_cemi_mcode_lrawreq_count += 1
            elif packet["KNX"].payload.cemi.message_code == 17:
                self.prop.flow_cemi_mcode_ldatareq_count += 1
            elif packet["KNX"].payload.cemi.message_code == 19:
                self.prop.flow_cemi_mcode_lpolldatareq_count += 1
            elif packet["KNX"].payload.cemi.message_code == 37:
                self.prop.flow_cemi_mcode_lpolldatacon_count += 1
            elif packet["KNX"].payload.cemi.message_code == 41:
                self.prop.flow_cemi_mcode_ldataind_count += 1
            elif packet["KNX"].payload.cemi.message_code == 43:
                self.prop.flow_cemi_mcode_lbusmonind_count += 1
            elif packet["KNX"].payload.cemi.message_code == 45:
                self.prop.flow_cemi_mcode_lrawind_count += 1
            elif packet["KNX"].payload.cemi.message_code == 46:
                self.prop.flow_cemi_mcode_ldatacon_count += 1
                
            elif packet["KNX"].payload.cemi.message_code == 47:
                self.prop.flow_cemi_mcode_lrawcon_count += 1
            elif packet["KNX"].payload.cemi.message_code == 247:
                self.prop.flow_cemi_mcode_mpropinfoind_count += 1
            elif packet["KNX"].payload.cemi.message_code == 251:
                self.prop.flow_cemi_mcode_mpropreadcon_count += 1
            elif packet["KNX"].payload.cemi.message_code == 252:
                self.prop.flow_cemi_mcode_mpropreadreq_count += 1
            elif packet["KNX"].payload.cemi.message_code == 245:
                self.prop.flow_cemi_mcode_mpropwritecon_count += 1
            elif packet["KNX"].payload.cemi.message_code == 246:
                self.prop.flow_cemi_mcode_mpropwritereq_count += 1
            elif packet["KNX"].payload.cemi.message_code == 240:
                self.prop.flow_cemi_mcode_mresetcon_count += 1
            elif packet["KNX"].payload.cemi.message_code == 241:
                self.prop.flow_cemi_mcode_mresetreq_count += 1
            else:
                self.prop.flow_cemi_mcode_other_count += 1
            
            if hasattr(packet["KNX"].payload.cemi.cemi_data, 'frame_type'):
                if packet["KNX"].payload.cemi.cemi_data.frame_type == 1:
                    self.prop.flow_cemi_ctrl1_sframe_count += 1
                else:
                    self.prop.flow_cemi_ctrl1_eframe_count += 1
                
            if hasattr(packet["KNX"].payload.cemi.cemi_data, 'repeat_on_error'):
                self.prop.flow_cemi_ctrl1_repeat_count += 1

            if hasattr(packet["KNX"].payload.cemi.cemi_data, 'broadcast_type'):
                self.prop.flow_cemi_ctrl1_broadcast_count += 1

            if hasattr(packet["KNX"].payload.cemi.cemi_data, 'priority'):
                priority = packet["KNX"].payload.cemi.cemi_data.priority
                if priority == 0:
                    self.prop.flow_cemi_ctrl1_prio0_count += 1
                elif priority == 1:
                    self.prop.flow_cemi_ctrl1_prio1_count += 1
                elif priority == 2:
                    self.prop.flow_cemi_ctrl1_prio2_count += 1
                elif priority == 3:
                    self.prop.flow_cemi_ctrl1_prio3_count += 1

            if hasattr(packet["KNX"].payload.cemi.cemi_data, 'confirmation_error'):
                self.prop.flow_cemi_ctrl1_error_count += 1

            if hasattr(packet["KNX"].payload.cemi.cemi_data, 'hop_count'):
                self.flow_array_hops.append(packet["KNX"].payload.cemi.cemi_data.hop_count)

            if hasattr(packet["KNX"].payload.cemi.cemi_data, 'source_address'):
                self.flow_array_cemi_src.append(packet["KNX"].payload.cemi.cemi_data.source_address)

            if hasattr(packet["KNX"].payload.cemi.cemi_data, 'destination_address'):
                self.flow_array_cemi_src.append(packet["KNX"].payload.cemi.cemi_data.destination_address)

            if hasattr(packet["KNX"].payload.cemi.cemi_data, 'object_type'):
                self.flow_array_cemi_mpropread_objType.append(packet["KNX"].payload.cemi.cemi_data.object_type)

            if hasattr(packet["KNX"].payload.cemi.cemi_data, 'object_instance'):
                self.flow_array_cemi_mpropread_objInstance.append(packet["KNX"].payload.cemi.cemi_data.object_instance)

            if hasattr(packet["KNX"].payload.cemi.cemi_data, 'property_id'):
                self.flow_array_cemi_mpropread_propId.append(packet["KNX"].payload.cemi.cemi_data.property_id)

            if hasattr(packet["KNX"].payload.cemi.cemi_data, 'number_of_elements'):
                if packet["KNX"].payload.cemi.message_code == 251 and packet["KNX"].payload.cemi.cemi_data.number_of_elements == 0:
                    self.prop.flow_cemi_mpropread_error_count += 1

            if hasattr(packet["KNX"].payload.cemi.cemi_data, 'packet_type'):
                if packet["KNX"].payload.cemi.cemi_data.packet_type == 0:
                    self.prop.flow_cemi_tpci_data_count += 1
                else:
                    self.prop.flow_cemi_tpci_other_count += 1

            if hasattr(packet["KNX"].payload.cemi.cemi_data, 'apci'):
                if packet["KNX"].payload.cemi.cemi_data.apci == 0:
                    self.prop.flow_cemi_apci_groupvalueread_count += 1
                elif packet["KNX"].payload.cemi.cemi_data.apci == 1:
                    self.prop.flow_cemi_apci_groupvalueresp_count += 1
                elif packet["KNX"].payload.cemi.cemi_data.apci == 2:
                    self.prop.flow_cemi_apci_groupvaluewrite_count += 1
                elif packet["KNX"].payload.cemi.cemi_data.apci == 3:
                    self.prop.flow_cemi_apci_indaddwrite_count += 1
                elif packet["KNX"].payload.cemi.cemi_data.apci == 4:
                    self.prop.flow_cemi_apci_indaddread_count += 1
                elif packet["KNX"].payload.cemi.cemi_data.apci == 5:
                    self.prop.flow_cemi_apci_indaddresp_count += 1
                elif packet["KNX"].payload.cemi.cemi_data.apci == 14:
                    self.prop.flow_cemi_apci_restart_count += 1
                elif packet["KNX"].payload.cemi.cemi_data.apci == 14:
                    self.prop.flow_cemi_apci_esc_count += 1
                else:
                    self.prop.flow_cemi_apci_other_count += 1

        if hasattr(packet["KNX"].payload, 'communication_channel_id'):
            self.flow_array_knxip_comchannel.append(packet["KNX"].payload.communication_channel_id)


    # The stats that have to be calculated after all packets of the flow have been received
    def final_stats(self):
        
        self.prop.flow_packets_count = len(self.flow_array_packets_all)
        self.prop.flow_packet_length_max = max(self.flow_array_packets_length, default=0)
        self.prop.flow_packet_length_min = min(self.flow_array_packets_length, default=0)
        if self.prop.flow_packets_count > 1:
            self.prop.flow_packet_length_mean = statistics.mean(self.flow_array_packets_length)
            self.prop.flow_packet_length_std = statistics.pstdev(self.flow_array_packets_length, self.prop.flow_packet_length_mean)
            self.prop.flow_packet_length_var = statistics.pvariance(self.flow_array_packets_length, self.prop.flow_packet_length_mean)

        self.prop.flow_duration = (self.prop.flow_end_timestamp - self.prop.flow_start_timestamp)/1000000000

        self.prop.flow_down_up_ratio = divide(len(self.flow_array_packets_forward), len(self.flow_array_packets_backward))

        self.prop.flow_knxip_count = len(self.flow_array_packets_knxip_all)
        self.prop.fw_knxip_count = len(self.flow_array_packets_knxip_forward)
        self.prop.bw_knxip_count = len(self.flow_array_packets_knxip_backward)
        self.prop.flow_knxip_down_up_ratio = divide(self.prop.fw_knxip_count, self.prop.bw_knxip_count)

        self.prop.flow_knxip_pps = divide(self.prop.flow_knxip_count, self.prop.flow_duration)
        self.prop.fw_knxip_pps = divide(self.prop.fw_knxip_count, self.prop.flow_duration)
        self.prop.bw_knxip_pps = divide(self.prop.bw_knxip_count, self.prop.flow_duration)

        self.prop.flow_knxip_bps = divide(self.prop.flow_knxip_bps, self.prop.flow_duration)
        self.prop.fw_knxip_bps = divide(self.prop.fw_knxip_bps, self.prop.flow_duration)
        self.prop.bw_knxip_bps = divide(self.prop.bw_knxip_bps, self.prop.flow_duration)

        self.prop.flow_knxip_comchannel_count = len(set(self.flow_array_knxip_comchannel))

        self.prop.flow_knxip_load_max = max(self.flow_array_knxip_load, default=0)
        self.prop.flow_knxip_load_min = min(self.flow_array_knxip_load, default=0)
        if len(self.flow_array_knxip_load) > 1:
            self.prop.flow_knxip_load_mean = statistics.mean(self.flow_array_knxip_load)
            self.prop.flow_knxip_load_std = statistics.pstdev(self.flow_array_knxip_load, self.prop.flow_knxip_load_mean)
            self.prop.flow_knxip_load_var = statistics.pvariance(self.flow_array_knxip_load, self.prop.flow_knxip_load_mean)

        self.prop.fw_knxip_load_max = max(self.fw_array_knxip_load, default=0)
        self.prop.fw_knxip_load_min = min(self.fw_array_knxip_load, default=0)
        if len(self.fw_array_knxip_load) > 1:
            self.prop.fw_knxip_load_mean = statistics.mean(self.fw_array_knxip_load)
            self.prop.fw_knxip_load_std = statistics.pstdev(self.fw_array_knxip_load, self.prop.fw_knxip_load_mean)
            self.prop.fw_knxip_load_var = statistics.pvariance(self.fw_array_knxip_load, self.prop.fw_knxip_load_mean)

        self.prop.bw_knxip_load_max = max(self.bw_array_knxip_load, default=0)
        self.prop.bw_knxip_load_min = min(self.bw_array_knxip_load, default=0)
        if len(self.bw_array_knxip_load) > 1:
            self.prop.bw_knxip_load_mean = statistics.mean(self.bw_array_knxip_load)
            self.prop.bw_knxip_load_std = statistics.pstdev(self.bw_array_knxip_load, self.prop.bw_knxip_load_mean)
            self.prop.bw_knxip_load_var = statistics.pvariance(self.bw_array_knxip_load, self.prop.bw_knxip_load_mean)
        
        self.prop.flow_knxip_load_bps = divide(sum(self.flow_array_knxip_load), self.prop.flow_duration)
        self.prop.fw_knxip_load_bps = divide(sum(self.fw_array_knxip_load), self.prop.flow_duration)
        self.prop.bw_knxip_load_bps = divide(sum(self.bw_array_knxip_load), self.prop.flow_duration)

        self.prop.flow_cemi_ctrl2_hops_max = max(self.flow_array_hops, default=0)
        self.prop.flow_cemi_ctrl2_hops_min = min(self.flow_array_hops, default=0)
        if len(self.flow_array_hops) > 1:
            self.prop.flow_cemi_ctrl2_hops_mean = statistics.mean(self.flow_array_hops)
            self.prop.flow_cemi_ctrl2_hops_std = statistics.pstdev(self.flow_array_hops, self.prop.flow_cemi_ctrl2_hops_mean)
            self.prop.flow_cemi_ctrl2_hops_var = statistics.pvariance(self.flow_array_hops, self.prop.flow_cemi_ctrl2_hops_mean)

        self.prop.flow_cemi_src_count = len(set(self.flow_array_cemi_src))
        self.prop.flow_cemi_dst_count = len(set(self.flow_array_cemi_dst))
        self.prop.flow_cemi_mpropread_objType_count = len(set(self.flow_array_cemi_mpropread_objType))
        self.prop.flow_cemi_mpropread_objInstance_count = len(set(self.flow_array_cemi_mpropread_objInstance))
        self.prop.flow_cemi_mpropread_propId_count = len(set(self.flow_array_cemi_mpropread_propId))

    #this will create the string and write it to a csv
    def write_flow_to_csv(self):
        csvfile.write(self.prop.dump())
        csvfile.write("\n")


def knxflowmeter(pcap_file, config):

    logging.info("KNXFlowMeter starts to process: " + pcap_file)

    global FLOW_TIMEOUT_SECONDS
    FLOW_TIMEOUT_SECONDS = config["General"]["FLOW_TIMEOUT_SECONDS"]

    global FLOW_TIMEOUT
    FLOW_TIMEOUT = FLOW_TIMEOUT_SECONDS*1000000000

    global packets
    packets = []

    csv_name = './unlabelled-csv/' + pcap_file.split('.')[0] + '_KNXFlows_' + str(FLOW_TIMEOUT_SECONDS) + '.csv'
    global csvfile
    csvfile = open(csv_name,'w')
    csvfile.write(KNXFlowProp().field_names_to_str())
    csvfile.write("\n")

    logging.info("Starting PCAP Splitter...")
    pcap_splitted_file_path, pcap_splitted_editpcap_file_path = split_packets(pcap_file, FLOW_TIMEOUT_SECONDS)
    logging.info("PCAP Splitter finished")

    TOTAL_PCAPS = len(os.listdir(pcap_splitted_editpcap_file_path))
    PCAPS = os.listdir(pcap_splitted_editpcap_file_path)
    i=0

    logging.info("Starting PCAP Flow Analysis...")
    for i in tqdm(range(TOTAL_PCAPS)):
        _pcap = PCAPS[i]
        i+=1
        packets = scapy_all.rdpcap(pcap_splitted_editpcap_file_path + '/' + _pcap)
        if len(packets) != 0:
            first_packet = packets[0]
            #if scapy_knx.KNX in first_packet: #if first_packet["UDP"].payload.name == "KNXnet/IP":
            if inet.UDP in first_packet or inet.ICMP in first_packet:
                KNXFlow(first_packet)
        else:
            continue
   
    logging.info("Finished PCAP Flow Analysis of " + pcap_file)
    os.system('rm -rf ' + pcap_splitted_file_path)

    csvfile.close()

    return csv_name
