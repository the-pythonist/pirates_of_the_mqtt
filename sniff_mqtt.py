import time
import paho.mqtt.client as paho
import pyshark
import threading
import asyncio


# function to begin live capturing
def live_capture(iface="Wi-Fi", out_file="test.pcapng"):
    new_loop = asyncio.new_event_loop()
    asyncio.set_event_loop(new_loop)

    capture = pyshark.LiveCapture(interface=iface, output_file=out_file)
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
mqtt_connect.connect(host='test.mosquitto.org', port=1883, keepalive=120)

mqtt_connect.on_connect = on_connect

mqtt_connect.loop_forever()
