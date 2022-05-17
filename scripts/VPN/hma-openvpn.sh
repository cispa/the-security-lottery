#!/bin/bash

scriptversion="0.5"
serverlist="/tmp/serverlist.txt"

# Save prompt settings, OpenVPN tends to brick the prompt
sttysettings=$(stty -g)

trap ctrl_c INT

# In case ctrl+c is pressed, restore terminal color and prompt settings, then exit
function ctrl_c()
{
	echo
	echo "Exiting script..."
	echo
	tput sgr0
	stty $sttysettings
	exit 0
}

# Function to show usage (available switches)
function showhelp()
{
	echo "- Available switches:"
	echo "  $0 -h = Show help"
	echo "  $0 -d = Daemonize OpenVPN"
	echo "  $0 -f = tests for and connects you to the fastest server"
	echo "  $0 -t = tests for and shows top 10 fastest servers"
	echo "  $0 -s = Shows OpenVPN status & IP"
	echo "  $0 -u = Updates this script"
	echo
	tput bold
	echo "- This script requires the following packages:"
	echo "  curl, openvpn, wget, dialog"
	echo
	tput sgr0
}

# Function to execute server latency test 
function pingtest
{
rm /tmp/pingtest* 2> /dev/null
echo
# If not fping package avail., advise to install and exit
if [[ $(which fping) == "" ]] ; then
echo "'fping' package not found!"
echo "Please install (apt-get install fping)"
echo
exit
fi

echo -n "Testing all servers for latency using fping"
# Download serverlist
curl -s -k https://vpn.hidemyass.com/vpn-config/l2tp/ > $serverlist

# How many servers do we have? (line count of serverlist)
servercount=$(wc -l $serverlist | awk '{print $1}')
i=1

# Extract server IPs and names from serverlist
while read line; do
	serverip=$(echo $line | awk '{print $1}')
	servername=$(echo $line | awk '{$1="";print $0}')
	# Test and save average latency for each server IP
	avg=$(fping -B 1.0 -t 300 -i 1 -r 0 -e -c 1 -q $serverip 2>&1 | awk -F'/' '{print $8}')
	# Save servername and latency to temp. result file
	echo "$servername = $avg" >> /tmp/pingtest.txt

	# Calculate percentage of server testing process
	percentage=$((($i*100)/$servercount));
	echo -ne "Testing all servers for latency using fping ($i \ $servercount) $percentage %  \033[0K\r"
	i=$((i+1))
done < $serverlist

# Re-order and sort latency test results, save to new temp result file
cat /tmp/pingtest.txt | awk -F[=] '{ t=$1;$1=$2;$2=t;print; }' | sort -n > /tmp/pingtest.txt.2

# Save all ping result file lines to final result file as long as they start with a ping value
while read line; do
	firstcol=$(echo $line | awk '{print $1}')
	re='^[0-9]+([.][0-9]+)?$'

	if [[ $firstcol =~ $re ]] ; then
		echo $line >> /tmp/pingtest.best.txt
	fi
done < /tmp/pingtest.txt.2

echo
# If we're not supposed to connect to VPN, just print top 10 servers
if [[ ! "$1" == "connect" ]] ; then 
	echo -e "\nTop 10 Servers by latency (ping)"
	echo "================================"
	cat /tmp/pingtest.best.txt | sort -n | head -10
	echo
	exit
else
	# If we're supposed to connect to VPN, save fastest server for later
	fastestserver=$(cat /tmp/pingtest.best.txt | head -1 | awk '{$1="";print}' | sed -e 's/^[[:space:]]*//')
	echo -e "Fastest server: $fastestserver\n"
	sleep 3
fi
}

# Function to check external IP
function checkip()
{
	ip=""
	attempt=0
	while [ "$ip" = "" ]; do
	        attempt=$(($attempt+1))
	        ip=`curl http://geoip.hmageo.com/ip/ 2>/dev/null`
	        if [ "$ip" != "" ]; then
	            if [ ! "$1" == "silent" ] ; then echo "- Current IP: $ip" ; fi
	        fi
	        if [ $attempt -gt 3 ]; then
	            if [ ! "$1" == "silent" ] ; then echo "- Failed to check current IP address." ; fi
	                exit
	        fi
	done
}

function updatenow
{
		echo -e "\n[ HMA! OpenVPN Script v$scriptversion - http://hmastuff.com/linux-cli ]\n\nChecking for new version..."
		rm /tmp/hma-openvpn.sh 2> /dev/null
		# Download hosted script version to temp file
                curl -s -k https://s3.amazonaws.com/hma-zendesk/linux/hma-openvpn.sh > /tmp/hma-openvpn.sh
                if [[ -f "/tmp/hma-openvpn.sh" ]] ; then
			# Extract script version from top of downloaded script
        	        updateversion=$(grep -m 1 'scriptversion=' /tmp/hma-openvpn.sh | awk -F'\042' '$0=$2')
		# If extracting script version failed, download of script must have failed. Advise and exit
                if [[ "$updateversion" = "" ]] ; then
	                echo -e "Unable to check for new version.\nPlease check your internet connectivity or try again later.\n"
	                exit 1
                fi

		# If hosted script version is newer than this script's version, replace this script
		if [[ $scriptversion < $updateversion ]] ; then
        	        echo "Updating v$scriptversion to v$updateversion ... "
	                chmod +x /tmp/hma-openvpn.sh && mv /tmp/hma-openvpn.sh .
	                echo "Done!"
                else
        	        echo -e "Already latest version. (v$scriptversion)\n"
                fi

                fi
                exit 0
 }


# If no su privileges available, try to get them
if [[ ! "$(whoami)" == "root" ]] ; then
	echo -e "\nHMA! OpenVPN Script v$scriptversion ]"

	# No sudo available? Then we can't get su privs. Advise and exit
	if [[ $(which sudo) == "" ]] ; then
		echo "'sudo' package missing! Please install."
		echo "e.g.: apt-get install sudo" 
		exit 1
	fi

	echo "Requesting su permissions..."
	# Run this script with sudo privs
	sudo $0 $*
		# If running this script with su privs failed, advise to do so manually and exit
		if [[ $? > 0 ]] ; then
		echo
		echo "Acquiring su permission failed!"
		echo "Please run this script with sudo permissions!"
		echo "(e.g. 'sudo $0' or 'sudo bash $0')"
		echo
		exit 1
	fi
exit 0
fi

# Check for which parameters this script was run with, act accordingly
while getopts "tfdhsu" parm
do
        case $parm in
	f)      pingtest connect
		;;

	t)	pingtest
		;;

        d)      daemonize=1
                ;;
	s)	if [ -z "$(pidof openvpn)" ] ; then
			echo -e "\n- OpenVPN is not running!"
		else
			echo -e "\n- OpenVPN is running."
		fi
		checkip
		echo
		exit 0
		;;
	u)	updatenow
		;;
        ?)      echo -e "\nHMA! OpenVPN Script v$scriptversion"
		echo -e "==================\n"
		showhelp
		exit 0
		;;
        esac
done


showtitle() {
clear
green="\e[36;5;82m"
stdcol="\e[0m"
echo -e "\n$green =============================="
echo " |     __  ____  ______    __ |"
echo " |    / / / /  |/  /   |  / / |"
echo " |   / /_/ / /|_/ / /| | / /  |"
echo " |  / __  / /  / / ___ |/_/   |"
echo " | /_/ /_/_/  /_/_/  |_(_)    |"
echo " |                            |"
echo " | HMA! OpenVPN Script v$scriptversion  |"
echo -e " ==============================\n"
echo "-> https://hidemyass.com/vpn"
echo -e "-> https://support.hidemyass.com$stdcol\n"
}

showtitle
showhelp

# Check what package managers are available, yum or apt-get. If both, use apt-get
pkgmgr=""
if [[ ! $(which yum) == "" ]] ; then
	pkgmgr="yum install"
fi
if [[ ! $(which apt-get) == "" ]] ; then
	pkgmgr="apt-get install"
fi

# Function to check for and install needed packages
function checkpkg
{
	if [[ $(which $1) == "" ]] ; then
		echo -n "Package '$1' not found! Attempt installation? (y/n) "
		read -n1 answer
		echo
		case $answer in
			y) $pkgmgr $1 
			;;
			n) echo -n "Proceed anyway? (y/n) "
			read -n1 answer2
			echo
			if [[ "$answer2" == "n" ]] ; then exit
			fi
			;;
		esac
	fi
}

# Check for all needed packages
checkpkg curl
checkpkg wget
checkpkg openvpn
checkpkg dialog
checkpkg fping

sleep 4
echo "- Getting HMA! Pro VPN serverlist..."
sleep 1

# Download serverlist to temp file
curl -k -s https://vpn.hidemyass.com/vpn-config/l2tp/ > $serverlist

# If no fastest server was specified, ask user to select a server via dialog
if [[ "$fastestserver" == "" ]] ; then

LINES=$(cat $serverlist | awk -F'\t' '{ print $2,"\t",$1 }')

IFS=$'\n\t'
dialog --backtitle "HMA! OpenVPN Script" \
--title "Select a server" \
--menu "Select a server" 17 90 15 $LINES 2>/tmp/server

response=$?
if [ $response == 255 ] || [ $response = 1 ]; then
	ctrl_c
fi

unset IFS

clear
# Set chosen server as connection target
hmaservername=$(cat /tmp/server | sed 's/ *$//')
hmaserverip=$(grep "$hmaservername" $serverlist | head -n1 | awk '{ print $1 }')

else
# If a fastest server was specified, use that as connection target
hmaservername=$fastestserver
hmaserverip=$(grep "$fastestserver" $serverlist | awk '{ print $1 }') 

fi

sleep 1
clear

# Ask user if he wants to connect via OpenVPN-TCP or OpenVPN-UDP
dialog --backtitle "HMA! OpenVPN Script" \
--title "Select OpenVPN protocol to use" \
--yes-label "UDP" --no-label "TCP" --yesno "Which protocol do you want to use?" 6 40
response=$?
case $response in
	0) echo "udp" > /tmp/hma-proto ;;
	1) echo "tcp" > /tmp/hma-proto ;;
	255) ctrl_c ;;
esac

sleep 1
clear

showtitle
hmaproto=`cat /tmp/hma-proto | tr '[:upper:]' '[:lower:]'`
echo "- Getting .ovpn template..."
echo
sleep 1
# Download *.ovpn template, then add chosen protocol and server IP to it
wget -O /tmp/hma-template.ovpn https://securenetconnection.com/vpnconfig/openvpn-template.ovpn >/dev/null 2>&1

echo "proto $hmaproto" >> /tmp/hma-template.ovpn

if [ "$hmaproto" == "udp" ]; then
	echo "remote $hmaserverip 553" >> /tmp/hma-template.ovpn
	hmaport=553
fi
if [ "$hmaproto" == "tcp" ]; then
	echo "remote $hmaserverip 443" >> /tmp/hma-template.ovpn
	hmaport=443
fi

checkip
sleep 1

echo -e "\n- Starting OpenVPN connection to:"
echo "  $hmaservername - $hmaserverip : $hmaport ($hmaproto) ..."
echo -e "  (Please enter your HMA! Pro VPN account username and password when asked)\n"

sleep 1

# If we're supposed to run as daemon, run OpenVPN in daemon mode as well
if [ "$daemonize" == "1" ]; then
openvpn --daemon --script-security 3 --config /tmp/hma-template.ovpn
echo -n -e "\n - Waiting for connection process to complete.."
sleep 5

oldip=$ip
ipattempt=0
while [ "$ipattempt" -lt "5" ]; do
	ipattempt=$(($ipattempt+1))
	echo -n "."
	checkip silent
	if [ ! "$ip" == "$oldip" ] ; then
		echo -e "\n - IP has changed ($oldip -> $ip)"
		echo "   Connection successful."
		ipattempt=5
	fi
	sleep 5
done

if [ "$ip" == "$oldip" ] ; then
echo -e "\nIP has not changed! Please check for possible network problems."
killall openvpn 2>/dev/null
ctrl_c
fi

echo -e "\nDisconnect via: 'sudo killall openvpn'\n"
else

# If we're not supposed to run as daemon, run OpenVPN the normal way
openvpn --script-security 3 --config /tmp/hma-template.ovpn
fi

# Exit script
ctrl_c

