sudo make clean; sudo make
sudo nfp-nffw load -s ccp.nffw
sudo rtecli design-load -f ccp.nffw -p nfp-build/pif_design.json -c ccp.p4cfg
