from kafka import KafkaConsumer
from kafka import KafkaProducer
from kafka.admin import KafkaAdminClient, NewTopic
from kafka.errors import KafkaError
import json

def create_kafka_topic(kafka_brokers, 
                       ca_cert, 
                       cert_file, 
                       key_file, 
                       
                       password, topic_name):
 
    try:
        admin_client = KafkaAdminClient(
        bootstrap_servers=kafka_brokers,
        security_protocol='SSL',
        ssl_check_hostname=False,
        ssl_cafile=ca_cert,
        ssl_certfile=cert_file,
        ssl_keyfile=key_file,
        ssl_password=password)


        topic = NewTopic(name=topic_name, num_partitions=1, 
        replication_factor=1)
        admin_client.create_topics([topic], validate_only=False)
        print(f"Topic '{topic_name}' created successfully.")
    except KafkaError as e:
        print(f"Error creating Kafka topic: {e}")

def produce_to_kafka_topic(kafka_brokers, 
                           ca_cert, 
                           cert_file, 
                           key_file, 
                           password, 
                           topic_name, 
                           messages
):
    try:
        producer = KafkaProducer(
        bootstrap_servers=kafka_brokers,
        security_protocol='SSL',
        ssl_check_hostname=False,
        ssl_cafile=ca_cert,
        ssl_certfile=cert_file,
        ssl_keyfile=key_file,
        ssl_password=password
        )
        for message in messages:
            producer.send(topic_name, json.dumps(message).encode('utf-8'))
        producer.flush()
        print(f"Messages sent to topic '{topic_name}' successfully.")
        return True
    except KafkaError as e:
        print(f"Error producing messages to Kafka topic: {e}")
        return False
    finally:
        producer.close()

def consume_from_kafka_topic(kafka_brokers, ca_cert, cert_file, 
key_file, password, topic_name):
    try:
        consumer = KafkaConsumer(topic_name,
        bootstrap_servers=kafka_brokers,
        security_protocol='SSL',
        ssl_check_hostname=False,
        ssl_cafile=ca_cert,
        ssl_certfile=cert_file,
        ssl_keyfile=key_file,
        ssl_password=password,
        group_id='my-consumer-group', # Specify a consumer group
        auto_offset_reset='earliest'
        )
        print(f"Consuming messages from topic '{topic_name}':")
        for message in consumer:
            print(message.value.decode('utf-8'))
    except KafkaError as e:
        print(f"Error consuming messages from Kafka topic: {e}")

if __name__ == "__main__":

    with open('conf/inf_config.json', 'r') as file:
        config  = json.load(file)
    kafka_brokers = config["kafka"]["brokers"]
    ca_cert = 'kafka_certs/ai4collab_CARoot.pem'
    cert_file = 'kafka_certs/ai4collab_certificate.pem'
    key_file = 'kafka_certs/ai4collab_RSAkey.pem'
    password = config["kafka"]["password"]
    topic_name = 'ai4fids.sc11.events'
    messages = ["Test 1", "Test 2", "Test 3"]

    # create topic
    #create_kafka_topic(kafka_brokers, ca_cert, cert_file, key_file, password, topic_name)

    #send messages to the previously created Kafka topic
    #produce_to_kafka_topic(kafka_brokers, ca_cert, cert_file, key_file, password, topic_name, messages)

    # Consume messages from Kafka topic
    consume_from_kafka_topic(kafka_brokers, ca_cert, cert_file, key_file, password, topic_name)
