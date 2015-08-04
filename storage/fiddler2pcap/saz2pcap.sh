for file in  $(ls  $1); 
	do cd $1;
	../fiddler2pcap.py -i $file  -o temp.pcap  --saz;  
	sudo tcprewrite --infile=temp.pcap --dlt=enet --outfile=temp2.pcap --enet-dmac=00:55:22:AF:C6:37 --enet-smac=00:44:66:FC:29:AF;  
	sudo tcprewrite --infile=temp2.pcap --outfile=${file%.saz}.pcap  --dstipmap=192.168.2.2:1.1.1.1 --srcipmap=192.168.2.2:1.1.1.1;
	rm temp.pcap;rm temp2.pcap;
	cd -;
done
