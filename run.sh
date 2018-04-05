#!/usr/bin/env bash

read -p 'host group: ' g

while true; do
    read -p ' Command: ' c
    ./rssh -host $g -exec "$c" |less -r
done
