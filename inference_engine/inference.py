import tensorflow as tf
import pandas as pd
import numpy as np
import logging
from .utils import load_config
from keras.models import load_model
import joblib
import argparse
from typing import List, Tuple, Dict, Any, Callable
import os
import json
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from kafka_utils.helpers import produce_to_kafka_topic
import pyfiglet
import warnings
from sklearn.exceptions import InconsistentVersionWarning


# supress annoying joblib warning
warnings.filterwarnings("ignore", category=InconsistentVersionWarning)

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger("AI4FIDS Inference")

# Constants
DEFAULT_CONFIG = {
    "model_path": "models/model.h5",
    "scaler_path": "models/scaler.joblib",
    "encoder_path": "models/label_encoder.joblib",
    "features_to_drop": ["flow_id", "src_ip", "dst_ip", "src_port", "dst_port"],
    "label_keyword": "label",
    "output_dir": "output",
    "mode": "offline",
    "paths": {
        "offline": "data/training/test.csv",
        "online": "temp/live_flows"
    },
    "kafka": {
        "enabled": False,
        "brokers": "ai4fids.kafka.com:9093",
        "ca_cert": "kafka_certs/CARoot.pem",
        "cert_file": "kafka_certs/certificate.pem",
        "key_file": "kafka_certs/RSAkey.pem",
        "password": "******",
        "topic": "ai4fids.sc1.2"
    }
}

VALID_MODE = ['online', 'offline']

class InferenceEngine:
    ''' 
    Class for building the inference engine.
    '''
    def __init__(self, config: Dict):
        '''
        Initializes the inference engine with required configurations.

        Parameters:
        - config (Dict): A dictionary containing the necessary paths and settings for inference.
        '''
        self.config = self._validate_config(config)
        self.model = self._load_model()
        self.scaler = self._scale()
        self.enc = self._encode()
        self.output_dir = self.config["output_dir"]
        self.flows_lst_dict = {}

    def _validate_config(self, config: Dict) -> Dict:
        """Ensure configuration is valid"""
        validated = DEFAULT_CONFIG.copy()
        validated.update(config)
        
        # Validate paths
        for path_key in ["model_path", "scaler_path", "encoder_path"]:
            if not os.path.exists(validated[path_key]):
                raise FileNotFoundError(f"Required file not found: {validated[path_key]}")
            
        if validated["mode"] not in VALID_MODE:
            raise ValueError(f"Invalid mode '{validated['mode']}'. Must be one of {VALID_MODE}.")
                
        return validated
    
    def _load_model(self) -> None:
        '''
        Load model from the specified path.
        '''
        logger.info(f"Loading model from {self.config['model_path']}")
        try:
            model = load_model(self.config['model_path'])
            logger.info("Model loaded successfully.")
            return model
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            raise

    def _scale(self):
        """Scale"""
        scaler = joblib.load(self.config["scaler_path"])
        return scaler

    def _encode(self):
        "Encode"
        enc = joblib.load(self.config["encoder_path"])
        return enc

    def _pre_processing(self, file_path) -> Tuple[np.ndarray, np.ndarray]:
        '''
        Preprocess, scale and encode data.
        '''

        data = pd.read_csv(file_path)
        data = data.dropna(axis=0, how='any')
        y = data[[self.config["label_keyword"]]]

        # store the flows as a list of dictionaries for future use
        self.flows_lst_dict = data.drop([self.config["label_keyword"]], axis=1).to_dict(orient='records')

        data = data.drop(self.config['features_to_drop'] + 
                         [self.config["label_keyword"]], axis=1
        )
        x = data.to_numpy()

        # scale
        x = self.scaler.transform(x)

        # encode
        #y = self.enc.transform(y.to_numpy().reshape(-1))

        return x, None

    def infer(self, file_path: str) -> List[Dict]:
        """
        Perform inference on a given dataset or a single instance

        Args:
            file_path (str): Path to the file.

        Returns:
            List[dict]: A list of dictionaries, where each dictionary contains:
                - "flow" (dict): A dict with the corresponding flows`.
                - "prediction" (str): The decoded class label.
                - "confidence" (float): The confidence score of the prediction.
        """
        try:
            # Preprocess the input data
            input_x, _ = self._pre_processing(file_path)

            # Perform inference
            logger.info("Performing inference...")
            prediction = self.model(input_x)
            pred = np.argmax(prediction, axis=1)

            # decoded prediction
            pred_dec = self.enc.inverse_transform(pred)

            # confidence score
            confidence = tf.reduce_max(prediction, axis=1).numpy()

            logger.info("Inference completed successfully.")
            return gen_dict(self.flows_lst_dict, pred_dec, confidence)
        except Exception as e:
            logger.error(f"Inference failed: {e}")
            raise

class FileChangeHandler(FileSystemEventHandler):
    '''
    Handler for file changes. It will used for tracking changes in the live-flow file,
    consumed by the inference engine.
    Args:
        - callback (callable). It will eventually call an InferenceEngine instance. Build in this generic
        way to enable any type of inference (or other) mechanism, when the flow csv file changes.
        - delay_interval (int). Introduces a delay between consecutive file changes to avoid duplicates
        Thus, the live flows should be updated not more frequently than delay_interval + a small margin
    '''
    def __init__(self, 
                 callback: Callable, 
                 delay_interval: int
        ):
        self.callback = callback
        self.last_processed_time = 0
        self.delay_interval = delay_interval

    def on_modified(self, event):
        '''
        Executed when the file is modified.
        '''
        current_time = time.time()

        # this check fixes a bug in linux, where changes in the directories act as trigger as well
        if event.is_directory:
            # Pandas tries to read and directory, throwing an error
            # Bug can also be fixed by catching 'IsADirectoryError' exception and the return
            return
        
        if (event.src_path.endswith('.csv') and 
            (current_time - self.last_processed_time < self.delay_interval)):
            return
        else:
            time.sleep(3.5) # wait a bit to ensure writing of file has been terminated
            logger.info(f"New flow detected. Inference will be performed.")
            self.callback(event.src_path)
            self.last_processed_time = current_time

def save_output(results: List[Dict], 
                timestamp: str, 
                output_dir:str
    ) -> None:
    '''
    Save inference output to a file.
    '''
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    output_path = os.path.join(output_dir, f"inference_results_{timestamp}.json")
    try:
        with open(output_path, 'w') as f:
            json.dump(results, f, indent=4)
        logger.info(f"Results saved to {output_path}")
    except Exception as e:
        logger.error(f"Failed to save results: {e}")

def parse_arguments():
    '''Create parser.
    '''
    parser = argparse.ArgumentParser(description='Inference engine')
    parser.add_argument('--config', 
                        type=str, 
                        default='conf/inf_config.json', 
                        help='Path to the config file'
    )
    parser.add_argument('--model_path', type=str, help='Path to model')
    parser.add_argument('--scaler_path', type=str, help='Path to scaler')
    parser.add_argument('--encoder_path', type=str, help='Path to encoder')
    parser.add_argument('--mode', type=str, help='Inference mode')

    return parser.parse_args()

def update_config(args, conf):
    '''
    Update config file via cli without changing it permanently
    '''
    for key in ['model_path', 'scaler_path', 'encoder_path', 'mode']:
        val = getattr(args, key, None)
        if val:
            conf[key] = val    
    return conf

def gen_dict(flows_lst_dict: List[Dict], 
             att_type: np.ndarray, 
             conf_score: np.ndarray
    ) -> List[Dict]:
    '''
    Generates a list of dicts, which will facilitate the 
    generation of the output of the infer() method.
    '''
    # convert to lists
    att_type.tolist()
    conf_score.tolist()
    if len(att_type)>1:
        # in case where multiple instances are passed at once, store them in a list
        # use float(confidence) to avoid JSON serialization issues
        return [{"flow_features": f, 
                 "attack_type": a, 
                 "confidence": float(c)} 
                 for f, a, c in zip(flows_lst_dict, att_type, conf_score)
                 ]
    else:
        return [{"flow_features": flows_lst_dict[0], 
                 "attack_type": att_type[0], 
                 "confidence": float(conf_score[0])}
                 ]

def handle_file_change(file_path: str, 
                       inference_engine: InferenceEngine,
                       kafka_config: dict = None
    ) -> None:
    """Used as the callback in FileChangeHandler. It calls the InferenceEngine"""
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    logger.info(f"------------ Modified event received: {file_path} ------------")
    output = inference_engine.infer(file_path)
    save_output(output, 
                timestamp, 
                inference_engine.output_dir
    )

    output_attack = gen_attack_list(output)

    # Send to Kafka if configured
    if kafka_config and kafka_config.get("enabled") and output_attack:
        success = produce_to_kafka_topic(kafka_config["brokers"], kafka_config["ca_cert"],kafka_config["cert_file"],kafka_config["key_file"],
            kafka_config["password"], kafka_config["topic"], output_attack)

        if success:
            logger.info("Sent to Kafka successfully")

def print_banner():
    ascii_banner = pyfiglet.figlet_format("AI4FIDS-Inf")
    print(ascii_banner)

def gen_attack_list(output, normal_kw="Normal"):
    "Return a list with attack instance only"
    output_attack = []
    for o in output:
        if o["attack_type"] != normal_kw:
            output_attack.append(o)
    return output_attack

def main():

    os.system("clear")
    print_banner()
    logger.info("AI4FIDS InferenceEngine will launch...")
    # parser
    args = parse_arguments()
    
    # load config
    config = load_config(args.config)
    config = update_config(args, config)

    # Get Kafka config (if exists)
    kafka_config = config.get("kafka", {})
    # instance of InferenceEngine
    inf_engine = InferenceEngine(config)

    mode = config['mode']
    file_path = config['paths'][mode]

    if mode=='online':
        # Inference online mode

        # Set up file system event handler. The inference is subtly performed below
        DELAY_INTERVAL = 2          
        event_handler = FileChangeHandler(
            callback=lambda file_path: handle_file_change(file_path, inf_engine, kafka_config),
            delay_interval=DELAY_INTERVAL
        )
        observer = Observer()
        observer.schedule(event_handler, 
                          path=file_path, 
                          recursive=False
        )
        observer.start()
        logger.info("Waiting for new live-flow...")
        try:
            while True:
                time.sleep(2)
        except KeyboardInterrupt:
            observer.stop()
        observer.join()
        
    elif mode=='offline':
        # Inference offline mode
        output = inf_engine.infer(file_path)

        # save results
        save_output(output, time.strftime("%Y%m%d-%H%M%S"), inf_engine.output_dir)
        
        # keep a list with attack instances only
        output_attack = gen_attack_list(output)
        #print(output_attack)

        # Kafka producer
        if kafka_config.get("enabled") and output_attack:
            produce_to_kafka_topic(kafka_config["brokers"], kafka_config["ca_cert"],kafka_config["cert_file"],kafka_config["key_file"],
            kafka_config["password"], kafka_config["topic"],output_attack)

if __name__ == "__main__":
    main()
