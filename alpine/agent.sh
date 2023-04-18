#!/bin/bash

AGENT_NAME="cocos-agent"
AGENT_PATH="$HOME/agent/$AGENT_NAME"

while true
do
    # find the process IDs of running processes based on their name
    if pgrep -x "$AGENT_NAME" >/dev/null; then
        echo "Executable $AGENT_NAME is already running."
    else
        if [ -x "$AGENT_PATH" ]; then
            echo "Executing $AGENT_NAME..."
            "$AGENT_PATH"
        else
            echo "Executable $AGENT_NAME not found at path $AGENT_PATH."
        fi
    fi
    
    # wait for 15 seconds before running the loop again
    sleep 15
done
