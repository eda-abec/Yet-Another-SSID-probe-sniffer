
IFACE=wlan0

all: prepare run

prepare:
	sudo rfkill unblock wifi
	sudo airmon-ng start $(IFACE)

run:
	@sudo python probe_request_sniffer.py $(IFACE)

log:
	@sudo python probe_request_sniffer.py $(IFACE) | tee -a probes.log
