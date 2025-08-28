# AppFlowMeter

A collection of modules that generate protocol-specific flow statistics. 

## Data folders
The AppFlowMeter needs and uses the following folders:
- `unlabelled-pcap`: This folder contains pcap files that need to be edited first in order to be processed by the AppFlowMeter modules. This folder is used only by the `utils/pcap_labelling.py` script, and in most cases you will not need it.
- `labelled-pcap`: This folder contains the pcap files that are ready to be processed by the AppFlowMeter modules. In most cases, you will need to put new pcaps into this folder in order to generate the corresponding flows.
- `unlabelled-csv`: This folder contains the output of the AppFlowMeter modules. For each pcap inside the `labelled-pcap` and each AppFlowMeter module, a corresponding csv is expected in the `unlabelled-csv` folder. It should be noted that the CSVs inside that folder are unlabelled, hence they need to be processed so that each flow to be classified as benign or as a specific attack.
- `labelled-csv`: This folder contains the output of the `utils/flow_labelling.py` script, i.e. the labelled CSVs, where each flow is associated with a specific class. The `utils/flow_labelling.py` reads the CSVs located in the `unlabelled-csv` folder.

## Installation

1. Clone the repo:
    ```shell
    git clone --recurse-submodule https://github.com/K3Y-Ltd/AppFlowMeter
    ```

2. Create a Python environment (make sure the `python-venv` package is already installed):
    ```shell
    python3 -m venv venv
    ```

3. Activate the environment and install the Python packages:
    ```shell
    $ cd AppFlowMeter
    $ source ./venv/bin/activate
    $ (venv) pip install -r requirements.txt
    ```

4. Install PcapPlusPlus with the following commands (check if a newer release of PcapPlusPlus is available):
    ```shell
    $ wget https://github.com/seladb/PcapPlusPlus/releases/download/v24.09/pcapplusplus-24.09-ubuntu-24.04-gcc-13.2.0-x86_64.tar.gz
    $ tar xzvf pcapplusplus-24.09-ubuntu-24.04-gcc-13.2.0-x86_64.tar.gz
    $ rm pcapplusplus-24.09-ubuntu-24.04-gcc-13.2.0-x86_64.tar.gz
    $ sudo cp ./pcapplusplus-24.09-ubuntu-24.04-gcc-13.2.0-x86_64/bin/PcapSplitter /usr/bin
    $ PcapSplitter -h
    $ rm -rf ./pcapplusplus-24.09-ubuntu-24.04-gcc-13.2.0-x86_64

    ```

5. Prepare prerequisites for traffic capture and CICFlowMeter
    ```shell
    $ sudo apt install default-jre wireshark-common libpcap-dev
    $ cd ./cicflowmeter/lib && sudo mvn install:install-file -Dfile=jnetpcap-1.4.r1425-1g.jar -DgroupId=org.jnetpcap -DartifactId=jnetpcap -Dversion=1.4.1 -Dpackaging=jar
    ```

6. Make sure you can run tcpdump without root privileges (https://medium.com/@hafizfarhad/fix-tcpdump-eth0-you-dont-have-permission-to-perform-this-capture-on-that-device-3941395be45c)

## Configuration

Configure AppFlowMeter by creating a `config.json` file and filling it accordingly (check bellow the template).

```json
{
    "General": {
        "FLOW_TIMEOUT_SECONDS": 120,
        "OPERATION_MODE": "ONLINE",
        "OFFLINE_PCAP_FILES": [],
        "OUTPUT_KAFKA": true,
        "ONLINE_CAPTURE_INTERFACE": "ens19",
        "ONLINE_CAPTURE_DURATION": "30s",
        "ONLINE_CAPTURE_PORTS_WHITELIST": [80],
        "FLOW_MODULES": ["CICFLOWMETER", "OCPPFLOWMETER"]
    },
    "Labelling": {
        "INPUT_CSV_FILES": [],
        "INPUT_PCAP_FILES": [],
        "Malicious_IP": ["192.168.21.225"]
    },
    "OCPPFlowMeter": {
        "CSMS_IP": "10.250.100.52",
        "CSMS_TCP_PORT": 80
    },
    "Kafka": {
        "KAFKA_HOST": "***",
        "KAFKA_PORT": 9092,
        "KAFKA_TOPIC_OCPPFLOWMETER": "uc1.ocppflowmeter.flows",
        "KAFKA_TOPIC_CICFLOWMETER": "uc1.cicflowmeter.flows",
        "KAFKA_SECURITY": "SASL_PLAINTEXT",
	    "KAFKA_SASL_USERNAME": "***",
	    "KAFKA_SASL_PASSWORD": "***",
        "KAFKA_CA": "./kafka_certs/CA.pem",
        "KAFKA_CERT": "./kafka_certs/cert.pem",
        "KAFKA_KEY": "./kafka_certs/key.pem",
        "KAFKA_PASSWORD": "***"
    }
}

```
| Parameter | Description | Allowed Values  | 
|-----------|-------------|-----------------| 
| `General.FLOW_TIMEOUT_SECONDS` | The flow timeout, i.e. the maxium duration of a flow. | Integer > 0 |
| `General.OPERATION_MODE`  | `ONLINE` means that the AppFlowMeter captures live data from a specified interface. `OFFLINE` mode means that the AppFlowMeter reads the pcaps included in the `labelled-csv` folder.  | Enum[`ONLINE`, `OFFLINE`]  |
| `General.OFFLINE_PCAP_FILES`  |  Specify the names of the pcap files that the AppFlowMeter should process (relevant to the `labelled-pcap` folder). Leave it empty, if the AppFlowMeter should read all the files inside the `labelled-pcap` folder. |  List of strings |
| `General.OUTPUT_KAFKA` | Activates the Kafka output. If true, the flows will be transmitted to the Kafka topics defined in the `Kafka` configuration section. | Boolean |
| `General.ONLINE_CAPTURE_INTERFACE` | When `ONLINE` is set, it specifies the network interface used to capture live traffic. | String |
| `General.ONLINE_CAPTURE_DURATION` | When `ONLINE` is set, it specifies the duration of the live traffic capture, in seconds. Each `ONLINE_CAPTURE_DURATION` seconds, the traffic capture is stopped and the pcap is delivered to the AppFlowMeter modules. | String (e.g., `10s`) |
| `General.ONLINE_CAPTURE_PORTS_WHITELIST` | When `ONLINE` is set, it specifies the TCP ports that should be whitelisted by `tcpdump`, aiming to reduce the amount of traffic that AppFlowMeter modules will proccess. | List of integers |
| `General.FLOW_MODULES` | Specifies the AppFlowMeter modules that should be used when running AppFlowMeter. | Enum[`OCPPFLOWMETER`, `CICFLOWMETER`, `KNXFLOWMETER`]. Only two modules are allowed at the same time, and only `CICFLOWMETER` can co-exist with other modules. |
| `Labelling.INPUT_CSV_FILES`  |  Optionally, you can specify which CSVs the `utils/flow_labelling.py` should process from the `unlabelled-csv` folder. If empty, all the CSVs inside that folder will be proccessed. |  List of strings |
| `Labelling.INPUT_PCAP_FILES` |  Optionally, you can specify which PCAPs the `utils/pcap_labelling.py` should process from the `unlabelled-pcap` folder. If empty, all the PCAPs inside that folder will be proccessed. |  List of strings |
| `Labelling.Malicious_IP`     |  A list of the IP addresses that should be considered malicious. Depending on the CSV that is processed by `utils/flow_labelling.py`, the corresponding label is applied automatically if one of the IP addresses of the list is present in the flow. | List of strings |

## Execution

1. Create the `labelled-pcap` and populate it with your PCAPs.

2. Make sure that `config.json` is tailored to your needs.

3. Run the AppFlowMeter: 
    ```shell
    (venv) python appflowmeter.py
    ```

4. When finished, the unlabelled flows should be in the `unlabelled-csv` folder. If you want to run the automatic labelling script, just run the `utils/flow_labelling.py`:
    ```shell
    (venv) python utils/flow_labelling.py
    ```

5. The labelled CSVs should be in the `labelled-csv` folder.
