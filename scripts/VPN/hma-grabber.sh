#!/bin/bash
# Colors
red="\033[1;31m" green="\033[1;32m" yellow="\033[1;33m" white="\033[1;37m" normal="\033[0m"
# permissions
if [ $USER != root ]; then echo -e $red"ERROR:$normal You need root privileges to continue... (sudo)" ; exit 0; fi
# Variables
TEMP=/tmp/temp.$$
trap 'rm -f $TEMP; exit 0' 0 1 2 3 15
tcp_files="https://www.hidemyass.com/vpn-config/TCP/"
udp_files="https://www.hidemyass.com/vpn-config/UDP/"

# Checking for required packages
curl=`which sed`
if [ "$curl" == "" ]; then echo -e $green"Installing sed..." && apt-get -y --force-yes install sed > nul
fi
curl=`which openvpn`
if [ "$curl" == "" ]; then echo -e $green"Installing openvpn..." && apt-get -y --force-yes install openvpn > nul
fi
curl=`which wget`
if [ "$curl" == "" ]; then echo -e $green"Installing wget..." && apt-get -y --force-yes install wget > nul
fi
curl=`which curl`
if [ "$curl" == "" ]; then echo -e $green"Installing curl..." && apt-get -y --force-yes install curl > nul
fi

# functions
function title () {
echo -e $green"====$yellow HMA-GRABBER$green ===="$normal; }
function show.progress () { i=0
while [ -r $TEMP ]; do clear; title
echo -e $yellow"Downloading $white$servers$yellow files:$white elapsed time $i seconds"$normal
let i=i+1; sleep 1; done; }
function start () { clear; title
echo -e $yellow"This script will download/update your HideMyAss OpenVPN configuration files."$normal
echo -e $white"Are you sure you wish to continue?$red (y/n)"$normal
stty -echo; read -n 1 RESP; stty echo; echo
case "$RESP" in
	y|Y)	clear; title
		read -p "Your HMA! username: " username; stty -echo
		read -p "Your HMA! password: " password; stty echo; echo
		echo -e $green"Checking servers and files:"
		tcp_servers=$(curl -s --compressed "$tcp_files" | grep -o '.ovpn"' | wc -l)
		udp_servers=$(curl -s --compressed "$udp_files" | grep -o '.ovpn"' | wc -l)
		servers=$[tcp_servers+udp_servers+crt_files+key_files]
		echo -e $yellow"TCP:$white $tcp_servers"; sleep 1
		echo -e $yellow"UDP:$white $udp_servers"; sleep 1
		touch $TEMP
		show.progress &
		rm rf /etc/openvpn/*.* > /dev/null 2>&1
		echo -e "$username\n$password" > /etc/openvpn/hmauser.pass
		wget --quiet -t 3 -T 20 -r -A.ovpn -nd --no-parent -e robots=off $tcp_files $udp_files -P /etc/openvpn/
		rm -f $TEMP
		echo -e $green"done!$white You can find the files in$yellow /etc/openvpn/"$normal; sleep 1
		echo -e $white"Credentials stored in$yellow /etc/openvpn/hmauser.pass"$normal; sleep 1
		echo -e $white"Applying settings..."$normal
		sed -i 's|auth-user-pass|auth-user-pass /etc/openvpn/hmauser.pass|g' /etc/openvpn/*; sleep 5
		sed -i '/show-net-up/d' /etc/openvpn/*; sleep 1
		sed -i '/dhcp-renew/d' /etc/openvpn/*; sleep 1
		sed -i '/dhcp-release/d' /etc/openvpn/*; sleep 1
		echo -e $green"All done!"$normal ;;
	n|N)	echo -e $green"Good bye!"$normal ;;
	*)	echo -e $red"ERROR:$normal $RESP is not an option."; sleep 2 ; start ;;
esac; }
# run script
start
