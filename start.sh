#!/bin/bash

# Open a new terminal and run pox.py
gnome-terminal --tab --command="bash -c 'python /opt/pox/pox.py --verbose ucla_cs118; $SHELL'"

# Open a new terminal and run mininet
gnome-terminal --tab --command="bash -c 'sudo python run.py; $SHELL'"

# Open a new terminal and run router.sh
gnome-terminal --tab --command="bash -c 'sudo bash ./router.sh; $SHELL'"
