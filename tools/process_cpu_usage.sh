#!/bin/bash

readonly ProcessName="gopacket_example"

ps -C $ProcessName -o pid,comm,etime,time
while true
do
    ps -C $ProcessName -o pid,comm,etime,time | grep -v ELAPSED
    sleep 1
done

