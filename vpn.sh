#!/bin/bash

CMD="./tvpn"
PID="./log/PID.txt"
LOG="./log/tvpn.log"
DEBUG="false"

# ---------------------------------------------------

function start {
	$CMD -debug=$DEBUG server.ini >> $LOG 2>&1 &
	tvpnpid=$!
	echo $tvpnpid > $PID
	echo "start [ok]"
}

function stop {
	kill `cat $PID`
	rm $PID
	echo "stop [ok]"
}

# --------------------------------------------------


echo "$CMD $1"

case "$1" in
start)
	sysctl net.ipv4.ip_forward=1
	iptables -t nat -A POSTROUTING -j MASQUERADE
	start
;;
start_debug)
	sysctl net.ipv4.ip_forward=1
	iptables -t nat -A POSTROUTING -j MASQUERADE
	DEBUG="true"
	start
;;
restart)
	if [ -f $PID ] ; then
		stop
		sleep 4
	fi
	start
;;
stop)
	stop
	exit 0
;;
esac


for (( c=0 ; ; c++ ))
do
	if [ -f $PID ] ; then
		tvpnpid=`cat $PID`
		cmdex="ps uh -p$tvpnpid"
		psrtn=`$cmdex`
		if [ -z "$psrtn" ]; then
			echo "`date '+%Y/%m/%d %H:%M:%S'` FATALERROR RESTART SERVICE" >> $LOG
			start
		elif (( $c%20 == 0 )); then
			echo "`date '+%Y/%m/%d %H:%M:%S'` PSINFO $psrtn" >> $LOG 
			c=0
		fi
		sleep 3 
	else
		break
	fi
done

