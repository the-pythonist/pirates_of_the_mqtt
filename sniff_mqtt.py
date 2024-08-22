import time
import paho.mqtt.client as paho
import pyshark
import threading
import asyncio
import argparse
import sys
import os


# Include Argparse for easy execution via shell
parser = argparse.ArgumentParser(prog="sniff_mqtt", description= "Script to begin sniffing MQTT packets",\
    usage=f"python3 {sys.argv[0]} -i INTERFACE [OPTIONS]", epilog="Enjoy! :)")

parser.add_argument("--interface", "-i", type=str, required=True, metavar="INTERFACE", help="specify interface to use for traffic collection")
parser.add_argument("--broker_ip", "-b", type=str, required=False, default="192.168.0.10", metavar="IP_ADDRESS", help="broker IP address to connect to")
parser.add_argument("--broker_port", "-p", type=str, required=False, default=1883, metavar="PORT", help="broker port to connect to, default is 1883")
parser.add_argument("--outfile", "-o", type=str, required=False, default=f"{os.getcwd()}/C1.pcapng", metavar="FILE_PATH", help="file to output traffic capture to")

args = parser.parse_args()
IP_ADDRESS = args.broker_ip
PORT = args.broker_port
INTERFACE = args.interface
OUTFILE = args.outfile


# function to begin live capturing
def live_capture(iface=INTERFACE, out_file=OUTFILE):
    new_loop = asyncio.new_event_loop()
    asyncio.set_event_loop(new_loop)

    capture = pyshark.LiveCapture(interface=iface, output_file=out_file, bpf_filter="port %s" % PORT)
    capture.sniff()


def on_connect(client, *lis):
    client.subscribe("#", qos=1)
    print("Subscription to all topics done")


# create a thread to concurrently run live_capture along main thread
thread_live_capture = threading.Thread(target=live_capture)
thread_live_capture.start()

# sleep so that LiveCapture() has enough time to initialize and start
time.sleep(2)

mqtt_connect = paho.Client(paho.CallbackAPIVersion.VERSION2, client_id='mqtt_client_1askldhfkashetui', clean_session=True, protocol=paho.MQTTv31)
mqtt_connect.max_inflight_messages_set(1)
# mqtt_connect.username_pw_set('txt', 'xtx')  # turns out connection happens without username/password
mqtt_connect.connect(host=IP_ADDRESS, port=PORT, keepalive=120)

mqtt_connect.on_connect = on_connect

mqtt_connect.loop_forever()
