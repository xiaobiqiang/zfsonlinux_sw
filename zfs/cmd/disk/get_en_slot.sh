#!/bin/bash 

function usage ()
{
    echo "usage: $0"
    exit 255
}

#echo $#
if [[ $# -gt 0 ]] ; then 
    usage
fi

sas3show | awk -F: '/Enclosure/{print $1, ":", substr($2,3,6)}; /Slot/{print $1, ":", $2}; /sas_address/{print "Addr :", substr($2,3,15)}'
qemu-x86_64 /usr/gnemul/qemu-x86_64/bin/MegaCli64 -PDList -aAll | awk -F: '/Enclosure Device ID/{print "Enclosure :", $2}; /Slot Number/{print "Slot :", $2}; /Inquiry Data/{sub(/^[ \t\r\n]+/,"",$2); print "Serial : ", substr($2,1,8)}'
#qemu-x86_64 /usr/gnemul/qemu-x86_64/bin/MegaCli64 -PDList -aAll | awk -F: '/Slot Number/{print "Slot :", $2}'
#qemu-x86_64 /usr/gnemul/qemu-x86_64/bin/MegaCli64 -PDList -aAll | awk -F: '/WWN/{print "WWN :", $2;}'
#qemu-x86_64 /usr/gnemul/qemu-x86_64/bin/MegaCli64 -PDList -aAll | awk -F: '/Inquiry Data/{ serial_num=substr($2,1,8); print "Serial :", serial_num;}'
#qemu-x86_64 /usr/gnemul/qemu-x86_64/bin/MegaCli64 -PDList -aAll | awk -F: -v wwn=$dk_wwn '/Enclosure Device ID/{en=$2};/Slot Number/{slot=$2}; /WWN/{if($2 == " "wwn) print en,slot,$2;}'
