import random
import time
import threading
from datetime import timezone, datetime

from scapy.contrib import mqtt
import scapy.all as scapy

import sqlite3
import paho.mqtt.client as mqtt

"Starting"
# First we definee variables
src_ip = "192.168.0.105"
dst_ip = "192.168.0.10"
dst_port = 1883

log_sub = 0

def state(active, code, description="", station="vgr", target=None):
    if target is None:
        data = '{\n\t"active" : %s,\n\t"code" : %s,\n\t"description" : "%s",\n\t' \
               '"station" : "%s",\n\t' % (active, code, description, station)
        print(data)
        data += new_ts()
    else:
        data = '{\n\t"active" : %s,\n\t"code" : %s,\n\t"description" : "%s",\n\t' \
           '"station" : "%s",\n\t"target" : "%s",\n\t' % (active, code, description, station, target)
        print(data)
        data += new_ts()
    return data


def new_ts():
    # function to generate new timestamps
    ts = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
    ts_ = f'"ts" : "{ts}"\n' + '}'
    return ts_


# what happens if a ConnAct packet is received? Then we subscribe
def on_connect(client, *lis):
    # IF a ConnAck is received, then we subscribe to our packets of interest as VGR
    [client.subscribe(x) for x in
     ("f/o/state/ack", "f/o/order", "f/o/nfc/ds", "fl/ssc/joy", "fl/mpo/ack", "fl/hbw/ack", "fl/sld/ack")]
    print("Chunk subscribe done")
    time.sleep(0.1)
    # Now we publish our fir
    data = '{\n\t"hardwareId" : "50F14AE8CF8D",\n\t"message" : "init",\n\t"softwareName" : "TxtFactoryVGR",\n\t' + \
           '"softwareVersion" : "0.8.1",\n\t"station" : "VGR",\n\t' + new_ts()
    client.publish("fl/broadcast", data, qos=1)


# #---


# What happens if a SubAck is received?
def on_subscribe(client, *lis):
    pass


# What happens when a publish message is sent from us and a puback has been received
def on_publish(client, userdata, msgid, *rest):
    match msgid:
        case 8:
            time.sleep(0.4)
            # Publish for f/i/state/hbw
            data = '{\n\t"active" : "0",\n\t"code" : "0",\n\t"description" : "",\n\t' + \
                   '"station" : "hbw",\n\t' + new_ts()
            client.publish("f/i/state/hbw", data, qos=1)

        case 9:
            # Publish for f/i/state/mpo
            data = '{\n\t"active" : "0",\n\t"code" : "0",\n\t"description" : "",\n\t' + \
                   '"station" : "mpo",\n\t' + new_ts()
            client.publish("f/i/state/mpo", data, qos=1)

        case 10:
            # Publish for f/i/state/sld
            data = '{\n\t"active" : "0",\n\t"code" : "0",\n\t"description" : "",\n\t' + \
                   '"station" : "sld",\n\t' + new_ts()
            client.publish("f/i/state/sld", data, qos=1)

        case 11:
            # Publish for f/i/state/vgr
            data = '{\n\t"active" : "0",\n\t"code" : "0",\n\t"description" : "",\n\t' + \
                   '"station" : "vgr",\n\t"target" : "hbw"\n\t' + new_ts()
            client.publish("f/i/state/vgr", data, qos=1)

        case 12:
            data = '{\n\t"active" : "0",\n\t"code" : "0",\n\t"description" : "",\n\t' + \
                   '"station" : "vgr",\n\t"target" : "mpo"\n\t' + new_ts()
            client.publish("f/i/state/vgr", data, qos=1)

        case 13:
            data = '{\n\t"active" : "0",\n\t"code" : "0",\n\t"description" : "",\n\t' + \
                   '"station" : "vgr",\n\t"target" : "dso"\n\t' + new_ts()
            client.publish("f/i/state/vgr", data, qos=1)

        case 14:
            data = '{\n\t"active" : "0",\n\t"code" : "0",\n\t"description" : "",\n\t' + \
                   '"station" : "vgr",\n\t"target" : "dsi"\n\t' + new_ts()
            client.publish("f/i/state/dsi", data, qos=1)

        case 15:
            data = state("0", "0", description="", station="dso")
            client.publish("f/i/state/dso", data, qos=1)

        case 16:
            data = '{\n\t"state" : "WAITING_FOR_ORDER",\n\t' + new_ts()[:-2] + ',\n\t"type" : "NONE"\n}'
            client.publish("f/i/order", data, qos=1)

        case 17:
            data = '{\n\t"history" : null,\n\t' + new_ts()[:-2] + ',\n\t"workpiece" : \n\t{\n\t\t"id" : "",\n\t\t' \
                   '"state" : "RAW",\n\t\t"type" : "NONE"\n\t}\n}'
            client.publish("f/i/nfc/ds", data, qos=1)

        # Case bundle for situation where same information (active=0,code=1) is sent in f/i/state/vgr
        case 18 | 23 | 26 | 27 | 28:
            (active, code) = (1, 2) if msgid in [18, 26] else (0, 1)
            data = state(active, code, "", "vgr", "")
            client.publish("f/i/state/vgr", data, qos=1)

        case 19 | 21 | 24 | 29 | 31 | 61 | 66 | 68 | 81:
            if msgid == 81:
                time.sleep(2)
            data = state(0, 1, "", "dsi")
            client.publish("f/i/state/dsi", data, qos=1)

        case 20 | 22 | 25 | 30 | 32 | 62 | 67 | 69:
            data = state(0, 1, "", f"dso")
            client.publish("f/i/state/dso", data, qos=1)

        case 33:
            data = '{\n\t"state" : "ORDERED",\n\t' + new_ts()[:-2] + ',\n\t"type" : "WHITE"\n}'
            client.publish("f/i/order", data, qos=1)

        case 34:
            data = '{\n\t"code" : 3,\n\t' + new_ts()[:-2] + \
                   ',\n\t"workpiece" : \n\t{\n\t\t"id" : "",\n\t\t"state" : "RAW",\n\t\t"type" : "WHITE"\n\t}\n}'
            client.publish("fl/vgr/do", data, qos=1)

        # case block to handle bulk cases where active, code, target is 0,1,hbw respectively
        case 35 | 38 | 40 | 41 | 42 | 44 | 46 | 48:
            if msgid == 38:
                time.sleep(7)
            if msgid == 40:
                time.sleep(1)
            if msgid == 41:
                time.sleep(1.5)
            if msgid == 42:
                time.sleep(10)
            if msgid == 46:
                time.sleep(0.2)
            if msgid == 48:
                time.sleep(1)
                
            data = state(0, 1, "", "vgr", "hbw")
            client.publish("f/i/state/vgr", data, qos=1)

    # case block to handle bulk cases where active, code, target is 1,2,hbw respectively
        case 36 | 37 | 39 | 40 | 42 | 43 | 45 | 47:
            if msgid == 37:
                time.sleep(2)
            if msgid == 43:
                time.sleep(3.5)
            if msgid == 45:
                time.sleep(2)

            data = state(1, 2, "", "vgr", "hbw")
            client.publish("f/i/state/vgr", data, qos=1)

        case 49:
            data = '{\n\t"code" : 4,\n\t' + new_ts()[:-2] + \
                   ',\n\t"workpiece" : \n\t{\n\t\t"id" : "",\n\t\t"state" : "RAW",\n\t\t"type" : "WHITE"\n\t}\n}'
            client.publish("fl/vgr/do", data, qos=1)

        # case block to handle bulk cases where active, code, target is 0,1,mpo respectively
        case 50 | 53 | 55 | 56 | 60 | 64 | 65 | 70 | 71 | 72 | 73 | 74 | 75:
            if msgid == 53:
                time.sleep(3.8)
            if msgid == 56:
                time.sleep(6)
            if msgid == 60:
                time.sleep(5.5)
            if msgid == 70:
                time.sleep(2.8)
            if msgid in [71, 72, 73, 74, 75]:
                time.sleep(10)

            data = state(0, 1, "", "vgr", "mpo")
            client.publish("f/i/state/vgr", data, qos=1)

        # case block to handle bulk cases where active, code, target is 1,2,mpo respectively
        case 51 | 52 | 54 | 59 | 63:
            if msgid == 52:
                time.sleep(2)
            data = state(1, 2, "", "vgr", "mpo")
            client.publish("f/i/state/vgr", data, qos=1)

        case 57:
            data = '{\n\t"state" : "IN_PROCESS",\n\t' + new_ts()[:-2] + ',\n\t"type" : "WHITE"\n}'
            client.publish("f/i/order", data, qos=1)

        case 58:
            data = '{\n\t"code" : 7,\n\t' + new_ts()[:-2] + \
                   ',\n\t"workpiece" : \n\t{\n\t\t"id" : "",\n\t\t"state" : "RAW",\n\t\t"type" : "WHITE"\n\t}\n}'
            client.publish("fl/vgr/do", data, qos=1)

        # case block to handle bulk cases where active, code, target is 0,1,dso respectively
        case 76 | 78 | 80:
            if msgid == 78:
                time.sleep(3.3)
            data = state(0, 1, "", "vgr", "dso")
            client.publish("f/i/state/vgr", data, qos=1)

        # case block to handle bulk cases where active, code, target is 1,2,dso respectively
        case 77 | 79:
            data = state(1, 2, "", "vgr", "dso")
            client.publish("f/i/state/vgr", data, qos=1)



        # case to send f/i/state/vgr information every 10 seconds when there is no process to fufill in FL
        case _:
            time.sleep(10)
            data = state(0, 1, "", "vgr", "hbw")
            client.publish("f/i/state/vgr", data, qos=1)



# What happens if a Publish Message is received? Then we send PubAck
# **** seems no need for below function. doc says that once on_message returns, a puback is implicity sent out to acknowledge the message
# def on_message(client, userdata, mqttmsg):
#     # this automatic behavior can be change by setting manual_ack=True in Client() and then using .ack to manually send puback
#     # -------------------
#     print(f"""A publish message was received from broker with the following signature
#     Client: {client}
#     Other: {mqttmsg}""")
#     client.ack(mid=mqttmsg.mid, qos=mqttmsg.qos)  #-- plan here is to take the mid and qos from the received message and place here





mqtt_connect = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id='TxtFactoryVGRV0.8.1', clean_session=True, protocol=mqtt.MQTTv31)
mqtt_connect.username_pw_set('txt', 'xtx')  # turns out connection happens without txt
mqtt_connect.connect(host=dst_ip, port=dst_port, keepalive=60)

mqtt_connect.on_connect = on_connect
mqtt_connect.on_subscribe = on_subscribe
mqtt_connect.on_publish = on_publish
# mqtt_connect.on_message = on_message  -- use this if manual_ack==True is ever set in mqtt.Client



mqtt_connect.loop_forever()