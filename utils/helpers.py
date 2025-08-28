from pcap_splitter.splitter import PcapSplitter
import os
import subprocess
from tqdm import tqdm
from pydantic import BaseModel


def split_packets(pcap_file, FLOW_TIMEOUT_SECONDS):
   pcap_splitted_file_path = './labelled-pcap/' + pcap_file.split('.')[0] + '_splitted'
   pcap_splitted_editpcap_file_path = pcap_splitted_file_path + '/' + str(FLOW_TIMEOUT_SECONDS) + "_timeout"
   os.system('mkdir ' +  pcap_splitted_file_path)
   os.system('mkdir ' +  pcap_splitted_editpcap_file_path)
   ps = PcapSplitter('./labelled-pcap/' + pcap_file)
   print(ps.split_by_session(pcap_splitted_file_path))  # This assures that all packets inside the PCAPs are in the same flow
   
   PCAPS = os.listdir(pcap_splitted_file_path)
   TOTAL_PCAPS = len(PCAPS)
   i=0

   for i in tqdm(range(TOTAL_PCAPS)):
      pcap = PCAPS[i]
      cmd = 'editcap -i ' + str(FLOW_TIMEOUT_SECONDS) + ' ' + pcap_splitted_file_path + '/' + pcap + ' ' + pcap_splitted_editpcap_file_path + '/' + pcap
      subprocess.call(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
      i+=1
   
   return pcap_splitted_file_path, pcap_splitted_editpcap_file_path


def divide(x, y):
   try:
      return float(x/y)
   except Exception:
      return float(0)


# This class holds the properties of a flow
class BaseFlowProp(BaseModel):

    def field_names_to_str(self):
        attributes = list(self.__class__.model_fields.keys())
        return ','.join(map(str, attributes))
    
    def __init__(self):
        super().__init__()

    def dump(self) -> str:
        all_values_in_string = ''
        for _, v in self.model_dump().items():
            all_values_in_string +=  str(v) + ','
        return all_values_in_string[:-1]
