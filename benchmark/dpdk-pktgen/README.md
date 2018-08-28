
DPDK pktgen
===========
K.I.S.S

## Build and run

	make RTE_SDK=/path/to/dpdk-sdk RTE_TARGET=build
	sudo ./build/pktgen -c fff -n 4 -- -c config -b 1 -f tx              # Send udp packets
	sudo ./build/pktgen -c fff -n 4 -- -c config -b 1 -f tx -t tracelist # Send tcp packets from pcap file
	sudo ./build/pktfen -c fff -n 4 -- -c config -b 1 -f rx

## Configuration file

	#
	# There are six cores and two ports are used.
	# And there are three queues enabled for each port.
	#
	
	# Settings for NIC-0
	core_id=0,port_id=0,queue_id=0 # CPU0 manages the queue 0 of NIC-0
	core_id=1,port_id=0,queue_id=1
	core_id=2,port_id=0,queue_id=2
	
	# Settings for NIC-1
	core_id=3,port_id=1,queue_id=0
	core_id=4,port_id=1,queue_id=1
	core_id=5,port_id=1,queue_id=2


## Notice

To replay tcp packets, all packets in pcap files should be sent in order
correctly, so pcap files should be sent in correct order.

## Acknowledge

Thanks to [@btw616](https://github.com/btw616) for his amazing work [dpdk-pktgen](https://github.com/btw616/dpdk-apps).
