PID := $(shell lsof -ti:8080)
#export

start:
	go build -o main # Build new binary.
	./main

run:
	# Build new binary.
	go build -o main
	# Signal restart.
	kill -SIGUSR2 $(PID)
	curl localhost:8080
