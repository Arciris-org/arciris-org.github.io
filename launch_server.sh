#!/bin/bash


if ! command -v python 2>&1 >/dev/null; then
	echo "Python is not installed. Please install Python to run the server"
	exit 1
fi


ROOT=

if [[ "$EUID" -ne 0 ]]; then
	echo "request sudo..."
	sudo -v
	ROOT=0
else
	ROOT=1
fi


if [[ "$ROOT" -eq 1 ]]; then
	python -m http.server 8080 >log.txt 2>&1  &
else
	sudo python -m http.server 8080 >log.txt 2>&1 &
fi

PID=$!

if [[ "$?" -eq 0 ]]; then
	echo "Server started http://0.0.0.0:8080"
else 
	echo "Server start failed"
	exit 1
fi

echo "Enter 'exit' to exit process."

while true; do
	read -p "> " val

	case "${val}" in
		"exit")
			printf "Killing python process..."
			kill "$PID"
			echo "done"
			break
			;;
		"" | "\n" | " ")
			continue;
			;;

		*)
			echo "Unknown Command: $val"
			continue
			;;
	esac
done


