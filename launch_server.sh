#!/bin/bash


if ! command -v python 2>&1 >/dev/null; then
	echo "Python is not installed. Please install Python to run the server"
	exit 1
fi

python -m http.server 8080 &
if [[ "$?" -eq 0 ]]; then
	echo "Server started http://127.0.0.1"
else 
	echo "Server start failed"
	exit 1
fi

wait

