#!/usr/bin/env bash

scrip_dir=$(cd "$(dirname "$0")"; pwd)
cd $scrip_dir
protocol=$1
module=$2
source=${scrip_dir%/*}

start()
  {
	echo "Start  tool.............................[ Begin ]"
	
	PROC_STR=`ps -ef | grep protocolsimulator| grep $source | grep -v grep`
	PID=`echo ${PROC_STR} |awk '{print $2}'`
	
	if [ "x${PID}" != "x" ] 
	then 
		echo "Tool is running, please stop it first!"
	else
		nohup python  $source/src/protocolsimulator.py $protocol $module >> ../log/sim.log 2>&1 &
		sleep 2

		PROC_STR=`ps -ef | grep protocolsimulator | grep $source | grep -v grep`
		PID=`echo ${PROC_STR} |awk '{print $2}'`
	
		if [ "x${PID}" != "x" ] 
		then
			echo "Starting successfully. pid:" ${PID}
			echo ${PID}> pid
		else
			echo "Starting failed, please check it."
		fi
		sleep 1 
	fi
	
	echo "Start tool ..............................[  End  ]"
  }


if [ $# -eq 2 ] ; then
    if [ "$2" = "client" -o  "$2" = "server" ] ; then
        start
    else
        echo "Wrong syntax!"
        echo "The usage is: startsim.sh <protocol> | [<client>  <server>]"
    fi
elif [ $# -eq 0 ] ; then
    echo "Usage: startsim.sh <protocol> | [client> <server]"
else
    echo "Wrong syntax!!"
    echo "Usage: startsim.sh <protocol> | [<client>  <server>]"
fi
