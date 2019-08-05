sudo make clean; sudo make
sudo nfp-nffw load -s payload_scan.nffw
sudo rtecli design-load -f payload_scan.nffw -p nfp-build/pif_design.json -c payload_scan.p4cfg
