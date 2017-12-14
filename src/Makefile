obj-m += proj3.o

kdir:=/lib/modules/$(shell uname -r)/build

all:
	make -C $(kdir) M=$(PWD) modules > /dev/null

clean:
	make -C $(kdir) M=$(PWD) clean

run:
	sudo dmesg --clear && sudo insmod ./proj3.ko && sleep 0.5 && cat /proc/lattop && sudo rmmod proj3 && dmesg

insert:
	sudo insmod ./proj3.ko

remove:
	sudo rmmod proj3

clear:
	clear

buildrun: all run

clone:
	rm linux -rf
	#git clone https://github.com/MHassanNadeem/linux.git

save_lattop:
	cat /proc/lattop > lattency_profile.txt
	
test: all
	@make remove > /dev/null 2>&1; (make insert && make clone && make save_lattop && make remove) > /dev/null