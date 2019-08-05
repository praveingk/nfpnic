sudo make clean; sudo make
sudo nfp-nffw load -s asm.nffw
sudo rtecli design-load -f asm.nffw -p nfp-build/pif_design.json -c asm.p4cfg
