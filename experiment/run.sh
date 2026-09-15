#!/bin/bash
# Fresh server per run to avoid dirty-state (destructive tests mutate the DB)
pkill -9 -f "[n]ode server.js" 2>/dev/null; sleep 0.5
cd /home/user/security_test/experiment/vulnapp
setsid node server.js > /tmp/vulnapp_run.log 2>&1 < /dev/null &
sleep 1.5
cd /home/user/security_test/experiment
node scanner.js
pkill -9 -f "[n]ode server.js" 2>/dev/null
