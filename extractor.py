import sqlite3
import os
import glob
import pyshark
import re

SQL_DB_PATH = "fl_mqtt.sqlite"
PCAPS_PATH = r"C:\Users\gadaw\PycharmProjects\test\fischer\pcaps"

def create_table(wp_location):
    # initialize database
    conn = sqlite3.connect(SQL_DB_PATH)
    cursor = conn.cursor()

    # create table based on the workpiece location
    cursor.execute(f"""CREATE TABLE IF NOT EXISTS {wp_location}(
                    time_delta_from_previous TEXT,
                    mqtt_qos            TEXT,
                    mqtt_topic          TEXT,
                    mqtt_payload        TEXT,
                    source_ip           TEXT)""")

    # ensure clean table
    cursor.execute(f"DELETE FROM {wp_location}")

    conn.commit()
    conn.close()

def insert_to_table(wp_location, delta_time_from_previous, mqtt_qos, mqtt_topic, mqtt_msg, source_ip):
    conn = sqlite3.connect(SQL_DB_PATH)
    cursor = conn.cursor()

    # begin insertion
    cursor.execute(f"""INSERT INTO {wp_location} (time_delta_from_previous, mqtt_qos, mqtt_topic, mqtt_payload, source_ip) 
                        VALUES (?, ?, ?, ?, ?)""", (delta_time_from_previous, mqtt_qos, mqtt_topic, mqtt_msg, source_ip))
    conn.commit()
    conn.close()


def extract_mqtt_packets(path_to_packets):
    for pcap_file in glob.glob(r'%s\*' % path_to_packets):
        mqtt_poi = []

        read_pcap = pyshark.FileCapture(input_file=pcap_file, display_filter='mqtt and mqtt.msgtype == 3')

        # first find the f/o/order topic. This is the topic used when an order gets sent from dashboard
        order_packet_timestamp = None
        is_order_packet_recorded = None

        previous_packet_ts = None

        for each_packet in read_pcap:
            try:
                for each_mqtt_layer in list(filter(lambda layer: layer.layer_name == "mqtt", each_packet.layers)):  ###
                    if each_mqtt_layer.topic == "f/o/order" and each_mqtt_layer.msgtype == '3':
                        is_order_packet_recorded = True

                        # record the time f/o/order was seen and then record subsequent packets relative from this
                        order_packet_timestamp = previous_packet_ts = round(float(each_packet.sniff_timestamp), 3)

                    if is_order_packet_recorded:
                        # qos=0 originates as publishes directly from SSC/broker (not clients) which we don't care about
                        if each_mqtt_layer.qos == '0':
                            continue
                        # calculate delta time of each packet from f/o/order (first) packet
                        delta_time = round(float(each_packet.sniff_timestamp), 3) - order_packet_timestamp
                        delta_time = round(delta_time, 3)

                        # calculate delta time of each packet from previous packet
                        delta_time_from_previous = round(float(each_packet.sniff_timestamp), 3) - previous_packet_ts
                        delta_time_from_previous = round(delta_time_from_previous, 3)
                        # now update the previous_packet_ts with current packet ts
                        previous_packet_ts = round(float(each_packet.sniff_timestamp), 3)

                        # convert message mqtt payload to string and store in overall list
                        _mqtt_msg_to_string = str(each_mqtt_layer.msg).replace(":","")  ### changed each_packet.mqtt to each_mqtt_layer
                        _mqtt_msg_to_string = bytes.fromhex(_mqtt_msg_to_string).decode('utf-8')    ###
                        mqtt_poi.append([delta_time_from_previous, str(each_mqtt_layer.qos), str(each_mqtt_layer.topic), _mqtt_msg_to_string, each_packet.ip.src])   ### changed each_packet.mqtt to each_mqtt_layer

            except AttributeError as error:
                continue

        # create table if necessary & insert extraction from each pcap file to database
        _ = re.search(r"(\w\w).pcapng", pcap_file).groups()[0]
        create_table(_)
        [insert_to_table(_, *x) for x in mqtt_poi]
        print("Done")

        read_pcap.close()


extract_mqtt_packets(PCAPS_PATH)
