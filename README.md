- [Introduction📌](#introduction)
- [Motivation](#motivation)
- [Objectives](#objectives)
- [Installation](#installation)
- [Literature Survey](#literature-Survey)
- [Implemented System](#implemented-system)
- [Description of the Implemented system](#description-of-the-implemented-system)
- [Software requirements specification](#software-requirements-specification)
- [System Design](#system-design)
- [Implementation](#implementation)
- [Testing](#testing)
- [Results & Discussion](#results-&-discussion)
- [Conclusion](#conclusion)
- [References](#references)
- [Appendix](#appendix)
<br>
<!-- --------------------------------------------------------------------------------------------------------------------------------------------------------- -->

<h2>Introduction📌</h2>

A distributed denial-of-service (DDoS) attack is a malicious attempt to disrupt the normal traffic of a targeted server, service, or network by overwhelming the target or its surrounding infrastructure with a flood of internet traffic.
DDoS attacks achieve effectiveness by utilizing multiple compromised computer systems as sources of attack traffic. Exploited machines can include computers and other networked resources such as IoT devices.
From a high level, a DDoS attack is like an unexpected traffic jam clogging up the highway, preventing regular traffic from arriving at its destination. It's critical to act soon after discovering a DDoS attack since it provides you the chance to avert significant disruption. The server can start to crash on waiting too long, and a full recovery might take hours.
The hardest part about mitigating a DDoS attack is that often it’s virtually impossible to do so without impacting legitimate traffic. This is because attackers go to great lengths to masquerade fake traffic as real.

<!-- --------------------------------------------------------------------------------------------------------------------------------------------------------- -->

<h2> Motivation</h2>

For enterprises operating at the edge with mission-critical activities that cannot afford downtime, DDoS mitigation as a protective layer is crucial. DDoS mitigation contributes to maintaining such activities' and services' ongoing availability. SDN allows for network design, construction, and operation. Attacks via distributed denial-of-service (DDoS) represent a serious risk to data centers.
New security concerns and assaults, particularly Distributed Denial of Service (DDoS) attacks, are frequently launched against SDN networks.

<!-- --------------------------------------------------------------------------------------------------------------------------------------------------------- -->

<h2>Objectives:</h2>
 
- To implement a network using mininet and Ryu controller
- To generate the dataset
- To apply Random Forest Machine learning algorithm to detect DDoS attack
- To add mitigation module

<!-- --------------------------------------------------------------------------------------------------------------------------------------------------------- -->

<h2>Installation</h2>

```bash
- install [Virtual box](https://www.virtualbox.org/wiki/Downloads) or VM-ware workstation

- install [Mininet-VM](https://github.com/mininet/mininet/releases/)

- install [Ubuntu](https://ubuntu.com/download/desktop) in virtual box

- install [ryu-controller](https://ryu.readthedocs.io/en/latest/getting_started.html) in ubuntu vm

- Use git clone to install the code files
```

```bash
git clone https://github.com/chiragbiradar/DDoS-Attack-Detection-and-Mitigation-using-Machine-Learning.git
```


<h3>Go to Ubuntu/ryu controller vm</h3> 

```bash
#check your IP address
ifcongif
# it should be something 198.162.XX.XX copy it
# change working directory to controller folder
cd controller

# switch on the ryu-controller
ryu-manager controller.py
```


<h3> Go to Mininet-vm</h3>

```bash
# change working directory to mininet folder
cd mininet

# change controller ip address that you copied from ryu controller ip
nano topology.py

# run topology
sudo python topology.py
```

<h3> hping commands</h3> 

```bash
# icmp flood
hping3 -1 -V -d 120 -w 64 -p 80 --rand-source --flood
```

```bash
# syn flood
hping3 -S -V -d 120 -w 64 -p 80 --rand-source --flood
```
```bash
# udp flood
hping3 -2 -V -d 120 -w 64 -p 80 --rand-source --flood
```

<p align="right">(<a href="#top">back to top</a>)</p>

<!-- --------------------------------------------------------------------------------------------------------------------------------------------------------- -->


<h2>Implemented System</h2>


### the Implemented system
To achieve the  goal of detection of DDoS attack and mitigation model for SDN networks, a model is build on the application plane. The architecture of implemented method consists of the flow collector module, feature extender module, anomaly detection module, and anomaly mitigation module. The task of the flow collector is to regularly collect information on traffic flow from the flow tables of each switch. These flow entries will be delivered to the feature extender, which will produce new features for each entry. 	

The anomaly detection module will receive the gathered data and use machine learning (ML) to perform flow-based detection and classify each flow as normal or abnormal. An aberrant flow  will be sent to the Mitigation module in order to stop the source of the attack, else no action will be taken.

In order to obtain traffic data, the flow collector first contacts the controller. When the controller receives a request for traffic information, it employs 

To gather data from flow tables,  openflow protocol is used. Every switch connected to the controller receives a flow-stats request from the controller, which asks the switch for flow statistics. As a result, each switch responds with a flow-stats reply message that includes all flow entries from all flow tables, each entry of which includes the flow description and any associated counters. The controller then replies to this component after compiling the traffic data from all the switches.

The flow collector parses the flow information after receiving it and discards any unnecessary data. The flow identifier (flow-id) and the flow counters are the pertinent data that are kept. The source IP address, destination IP address, source MAC address, destination MAC address, TCP/UDP source port, TCP/UDP destination port, and transport protocol identification make up the seven-tuple that is  referred to as the flow-id (protocol). It's crucial to remember that this tuple can be modified to meet the requirements of the network infrastructure.

<!-- --------------------------------------------------------------------------------------------------------------------------------------------------------- -->

<h2>Software requirements specification</h2>


<!-- --------------------------------------------------------------------------------------------------------------------------------------------------------- -->

<h3> Overview of SRS:</h3>

Software Requirement Definition (SRS) is a comprehensive specification and description of the software requirements that must be met for the software systems to be developed successfully. Depending on the sort of demand, they may be both functional and non-functional. In order to thoroughly grasp the demands of consumers, contact between various customers and contractors is done.

<!-- --------------------------------------------------------------------------------------------------------------------------------------------------------- -->

<h4> Requirement Specification:</h4>

<!-- --------------------------------------------------------------------------------------------------------------------------------------------------------- -->

<h4>Functional Requirement:</h4>

- Machine learning model should be able to detect DDoS attacks
-  Communicate with the controller to request traffic information
- Mitigate the DDoS attack without restricting the normal traffic

<h4>Non-Functional Requirement:</h4>

-  Detect DDoS attack within 20 seconds
- Analyze traffic data every 5 seconds to classify traffic as normal or abnormal.
- Mitigate the malicious traffic in 2 minutes to detect its port number.

<!-- --------------------------------------------------------------------------------------------------------------------------------------------------------- -->

<h3>Software and Hardware requirement specification:</h3>

- Windows/ Linux/ macOS
- Virtualization software (VMware/virtual box)
- Ryu controller
- Mininet software
- Wire shark (for network monitoring)

<!-- --------------------------------------------------------------------------------------------------------------------------------------------------------- -->

<h2>System Design</h2>

<!-- --------------------------------------------------------------------------------------------------------------------------------------------------------- -->

<h3>Architecture of the System</h3>
Software-Defined Networking (SDN) is a network architecture approach that enables the network to be intelligently and centrally controlled, or 'programmed,' using software applications

<!-- --------------------------------------------------------------------------------------------------------------------------------------------------------- -->

<h4>SDN architecture includes three layers: </h4>


<!-- --------------------------------------------------------------------------------------------------------------------------------------------------------- -->

<h4>Application layer:</h4>

The application layer is where the network applications, such as network management, traffic engineering, and security, are implemented.

<!-- --------------------------------------------------------------------------------------------------------------------------------------------------------- -->

<h4>Control layer:</h4>

The control layer represents the centralized SDN controller software that acts as the brain of the 
software-defined networking. This controller resides on a server and manages policies and traffic flows throughout the network.

<!-- --------------------------------------------------------------------------------------------------------------------------------------------------------- -->

<h3>Architecture of the System</h3>
### Infrastructure layer:
The infrastructure layer is made up of the physical switches or routers in the network which forward traffic according to the instructions from the control plane.

<!-- --------------------------------------------------------------------------------------------------------------------------------------------------------- -->

<h3> Activity Diagram</h3>


<!-- --------------------------------------------------------------------------------------------------------------------------------------------------------- -->

<h3> Dataset Features Description:</h3>

Dataset is generated using python scripts for malicious traffic and legitimate traffic
- Dataset size = 22 columns x 2667523 rows
- Data description:
- Ip_source - source IP address
- Ip_dst - destination IP address
- Icmp_type 
- Flow duration 
- Idle time 
- Packet_count 
- Label - classify malicious or legitimate traffic(1=legitimate & 0=malicious)

<!-- --------------------------------------------------------------------------------------------------------------------------------------------------------- -->

<h2> Implementation</h2>


<!-- --------------------------------------------------------------------------------------------------------------------------------------------------------- -->

<h3>Implemented Methodology</h3>

<!-- --------------------------------------------------------------------------------------------------------------------------------------------------------- -->

<h4>Explanation:</h4>

The Implemented system consists of a detection module and a mitigation module. The model is trained  on the dataset that is  generated .

To generate the dataset, a topology in SDN using mininet. simulated network traffic(normal traffic and anomalous traffic) is created. Then feature's source IP, destination IP, port number, and timestamp from the packets using the RYU controller are extracted.

<!-- --------------------------------------------------------------------------------------------------------------------------------------------------------- -->
<!-- --------------------------------------------------------------------------------------------------------------------------------------------------------- -->

<!-- --------------------------------------------------------------------------------------------------------------------------------------------------------- -->

<h4>Traffic Control module:</h4>

In order to obtain traffic data, the Flow Collector first contacts the controller. When the controller receives a request for traffic information, it employs To gather data from flow tables, 1use OpenFlow protocol. Every switch connected to the controller receives a flow-stats request from the controller, which asks the switch for flow statistics. As a result, each switch responds with a flow-stats reply message that includes all flow entries from all flow tables, each entry of which includes the flow description and any associated counters. The controller then answers this component after compiling the traffic data from all the switches. The Flow Collector parses the flow information after receiving it and discards any unnecessary data. The flow identifier (flow-id) and the flow counters are the pertinent data that are kept. The source IP address, destination IP address, source MAC address, destination MAC address, TCP/UDP source port, TCP/UDP destination port, and transport protocol identification make up the seven-tuple that is referred to as the flow-id (protocol). It's crucial to remember that this tuple can be modified to meet the requirements of the network infrastructure. Only three counters—the packet count, byte count, and duration—are included in the OpenFlow flow counters.

<!-- --------------------------------------------------------------------------------------------------------------------------------------------------------- -->

<h4>Detection module:</h4>

Depending on the source of the data to be studied or the method used to identify anomalous occurrences, there are several categories that might be used to classify intrusion detection. Flow-based or packet-based detection is employed depending on the data to be processed, and depending on the detection method, signature-based or anomaly-based detection can be utilized.

Flow-based detection was selected based on the source of the data to be evaluated since it would be more suited for high-speed networks and more effective than packet-based detection in terms of processing and memory overhead.

Anomaly-based intrusion detection is implemented  as a detection method, and more specifically, detection with ML.

<!-- --------------------------------------------------------------------------------------------------------------------------------------------------------- -->

<h4>Mitigation module:</h4>

Once a malicious flow has been verified by the anomaly detection module, the Anomaly Mitigation module is in charge of implementing mitigation measures to prevent network disruption or performance degradation. In the  framework, attack at its source is stopped. The preventing attacks caused by IP spoofing does not necessarily involve banning the attackers' IP addresses. For proof-of-concept purposes, in this case,   attacker's Ethernet address is blocked.

<!-- --------------------------------------------------------------------------------------------------------------------------------------------------------- 

<!-- --------------------------------------------------------------------------------------------------------------------------------------------------------- -->


<!-- --------------------------------------------------------------------------------------------------------------------------------------------------------- -->

<h2> Results & Discussion</h2>

After designing the attack detection and mitigation method,the results are tested and evaluated.  The evaluation of the framework includes the evaluation of the different ML algorithms, and a comparison of the different models used. The below table shows the accuracies of different models used:


From the above table, it can be seen that random forest gives the best accuracy to categorize normal and malicious traffic.

In order to evaluate the performance of the model,  a test is performed by process of online traffic classification and attack mitigation. For mitigating attacks, firewall rules were set to block attacks that were detected. Thus, for every flow detected as malicious, a firewall rule is installed to block the Ethernet address from which the attack is launched.  The Python code of the generated prototype is implemented , and then normal traffic is generated as background traffic, and DDoS attack is detected.

Results from the below graph shows that after the traffic is launched it is collected and detected and firewall rules were installed to block the source attack.After this point all the attacks generated from the source were blocked without affecting normal traffic.

<!-- --------------------------------------------------------------------------------------------------------------------------------------------------------- -->

<h2>Conclusion</h2>
 
In this work, a random forest machine learning algorithm is used to develop a model that can automatically identify and mitigate DDoS assaults in SDN networks. All of the traffic flow entries are regularly collected by the model, which then extracts the native flow features and expands them by including additional features. A detection module uses five criteria to categorize each flow as normal or anomalous. When an attack is discovered, its source is prevented. Three ML algorithms were assessed with regard to the classification ML method utilized in the detection module, including random forest, SVM, and KNN.
The outcomes of the experiment demonstrated that RF is the best classifier for the generated network. Without disrupting regular traffic, the implemented methodology proved effective at swiftly and correctly identifying and thwarting threats.

<h3>Glossary</h3>
- DDoS:It is a type of cyber attack that is carried out by flooding the target website or network with a large amount of traffic from multiple sources, with the aim of overwhelming the system and making it unavailable to users 
- Network Virtualization:Network virtualization is a technology that allows multiple virtual networks to be created and run on top of a physical network infrastructure.
- SDN:Network virtualization is a technology that allows multiple virtual networks to be created and run on top of a physical network infrastructure.
- Data Plane:the part of a network that is responsible for forwarding traffic between devices.
- Network Plane:it often refers to be as control plane
- Routers:device that is responsible for forwarding traffic between different networks.
- MAC address:It is a hardware address that is burned into the network interface during the manufacturing process, and it is used to identify the device on a network
- IP Address:it provides the location of the host in the network
- SYN Flood which is used to initiate a TCP connection, but not completing the final step of the process.
- ICMP Floodan ICMP echo request is a message that is sent to a network device to determine whether it is reachable and responding.
- SMURF Flood:sending large number of of icmpv4 flood
 UDP Flood:it and making it unavailable to legitimate users

<!-- --------------------------------------------------------------------------------------------------------------------------------------------------------- -->

<h3>Description of Tools & Technology used</h3>

- Mininet:Mininet is a tool for software-defined networks.
- RYU controller:Ryu Controller is an open, software-defined networking (SDN) Controller designed to increase the agility of the network by making it easy to manage and adapt how traffic is handled.
- Virtual Box:Virtualization software
- Linux:Operating system
- Python:Programming Language
- Wireshark:Network Monitoring tool
