sudo make clean; sudo make
sudo nfp-nffw load -s virt.nffw
sudo rtecli design-load -f virt.nffw -p nfp-build/pif_design.json -c virt.p4cfg
