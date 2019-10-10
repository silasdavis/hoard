#!/usr/bin/env bash

export PATH=$PATH:$(pwd)/bin

hoard config memory -s test:secret_pass | hoard -c- &> /dev/null &
HID=$!
function finish {
    kill -TERM $HID
}
trap finish EXIT

npm test