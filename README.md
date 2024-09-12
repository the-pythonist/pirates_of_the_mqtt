# Pirates of the MQTT: Raiding IIoT Systems with a Rogue Client

**Pirates of the MQTT: Raiding IIoT Systems with a Rogue Client**

Case study using Fischertechnik's Lernfabrik 4.0 (9V).

## This repository includes:
- The script to sniff mqtt packets and store them into .pcap files (`sniff_mqtt.py`).
- The script to extract mqtt information (topic, payload, qos) from recorded .pcap files into an sqlite database (`extractor.py`).
- The script to carry out the MQTT rogue client attack against the Fischertechnik Lernfabrik (`attack_order.py`).
- The malicious program to upload to the VGR along with the malicious config file to upload to the VGR (`TxtParkPosVGR` and `Config.ParkPos.json`)

#### Due to the large sizes of the .pcap files, they are not provided in this repo. Only the SQLite database file is provided.

## How to use it?
- To quickly run the attack directly from the provided database, simply run:

	```python3 attack_order.py```

- In case you would like to run the entire chain of scripts, run the scripts in the following order:
	1. `python3 sniff_mqtt.py -i [INTERFACE_HERE]` -- this needs to be run individually for each packet capture of an order. See the `-o` flag to specify the output file for the traffic capture.
	2. `python3 extractor.py`
	3. `python3 attack_order.py`

#### Each of the scripts come with flags/options to help customize the usage of the script. To view these options, please run the script with `--help`.


## Required Packages
These packages refer to packages outside of the Python built-in packages that is required for the successful run of the scripts.
- For just running the main attack (i.e., the `attack_order.py` script)):
	- `aiomqtt`
	- `paramiko`
	- `scp`

- For running the entire chain of files:
	- `aiomqtt`
	- `paramiko`
	- `scp`
	- `pyshark`
	- `glob`
	- `paho-mqtt`
	

### Steps to Run
- Clone the GitHub repo.
- Navigate to the cloned directory contain project files.
- Run the script:
     ```
     python3 attack_order.py
     ```


---

### ⚡[Video](https://youtu.be/alKavJ9x6VY)


**Disclaimer:** This project is intended for educational purposes only. Unauthorized use of these scripts for malicious purposes is illegal and unethical. Always obtain proper authorization before testing security on any system.




<img src="https://github.com/rnrn0909/beyondthelens/assets/57967202/236eb741-b6dc-4f8a-89b1-ebfc66ee2a2e" align="right" width="260" height="40">
