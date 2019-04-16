#!/bin/env bash

if [ "$1" = "user1" ]
then
	`perl -pi -e 's/3GPP-GGSN-Address.*/3GPP-GGSN-Address:211.246.121.162/' ../conf/diameter.cfg`
	`perl -pi -e 's/Framed-IP-Address.*/Framed-IP-Address:10.132.233.119/' ../conf/diameter.cfg`
elif [ $1 = 'user2' ]
then
	`perl -pi -e 's/3GPP-GGSN-Address.*/3GPP-GGSN-Address:166.147.123.109/' ../conf/diameter.cfg`
	`perl -pi -e 's/Framed-IP-Address.*/Framed-IP-Address:10.221.97.198/' ../conf/diameter.cfg`
elif [ $1 = 'user3' ]
then
	`perl -pi -e 's/3GPP-GGSN-Address.*/3GPP-GGSN-Address:166.147.123.107/' ../conf/diameter.cfg`
	`perl -pi -e 's/Framed-IP-Address.*/Framed-IP-Address:10.140.217.129/' ../conf/diameter.cfg`
elif [ $1 = 'user4' ]
then
	`perl -pi -e 's/3GPP-GGSN-Address.*/3GPP-GGSN-Address:211.246.121.162/' ../conf/diameter.cfg`
	`perl -pi -e 's/Framed-IP-Address.*/Framed-IP-Address:10.132.4.168/' ../conf/diameter.cfg`
elif [ $1 = 'user5' ]
then
	`perl -pi -e 's/3GPP-GGSN-Address.*/3GPP-GGSN-Address:221.177.253.16/' ../conf/diameter.cfg`
	`perl -pi -e 's/Framed-IP-Address.*/Framed-IP-Address:10.55.27.22/' ../conf/diameter.cfg`
else
	`perl -pi -e 's/3GPP-GGSN-Address.*/3GPP-GGSN-Address:166.147.123.110/' ../conf/diameter.cfg`
	`perl -pi -e 's/Framed-IP-Address.*/Framed-IP-Address:10.228.183.180/' ../conf/diameter.cfg`
fi
