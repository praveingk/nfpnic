### Use-Cases only for Smart NICs
1) Host-based Congestion-control.
2) Virtualization (e.g. VXLAN, GRE, VFP)
3) Service Chaining.
4) Network routing based on data-locality (routing to a certain core on the host, where the related data is present).
5) Deep-packet Inspection (when payload is encrypted).
6) RDMA-based applications.
7) Application Acceleration (micro-services on the FPGA of nic).


### Use-cases common for Smart NICs or Programmable switches 
1) Data distribution offload.
2) Network Functions  (e.g. SLB, firewalls, NAT, etc).
3) Network Security (DDoS, IDS , etc).
4) Computation based on network data.


### Primitives for NIC

#### 1) Encapsulation (or Virtualization) : 
This primitive will add a new header (gre) to the packet at a particular location of the header-stack.

#### 2) Congestion Control Aides : CCP[Sigcomm '18]
This is a set of primitives which monitor various metrics of tcp flows in smart-nic to provide regular feedback to a control plane.

#### 3) Payload Scan : 
This primitive searches for a pattern in the payload and increments a counter if it matches. One problem with doing this in smart-nic as opposed to tofino is that, this reduces the throughtput of the effective packets by upto 90%.

#### 4) Encryption :
Ideally, netronome supports IPSec, still figuring out how to encrypt/decrypt.

### Steps to execute a program in Netronome Nic:

1) Load the nfp kernel module :
```shell
     sudo modprobe nfp nfp_pf_netdev=0 nfp_dev_cpp=1
```
2) Start the run-time environment :
```shell
     sudo systemctl start nfp-sdk6-rte
     sudo systemctl start nfp-sdk6-rte-debug
```
3) Build the program using the below command :
```shell
     sudo nfp4build -s AMDA0096-0001:0 -l lithium -o <prog_name>.nffw -p nfp-build -4 <prog_name>.p4 
```
4) Load the firmware using the command :
```shell
     sudo nfp-nffw load -s <prog_name>.nffw
```
5) Load the design on the nic : 
```shell
     sudo rtecli design-load -f <prog_name>.nffw -p nfp-build/pif_design.json -c user_config.json
```

Now you must see the vf interfaces in ifconfig.

