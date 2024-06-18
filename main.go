package main

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	MaxBytesSize    = 1 << 20 // 1 MB
	readTimeout     = 5 * time.Second
	shutdownTimeout = 5 * time.Second
	handlerTimeout  = 5 * time.Second
)

func main() {
	log.Println("Started HTTP API, PID: ", os.Getpid())
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(rw http.ResponseWriter, r *http.Request) {
		log.Printf("New request! From: %d, path: %s, method: %s: ", os.Getpid(),
			r.URL, r.Method)
	})

	listenAndServe(":8080", mux)
}

func listenAndServe(port string, handler http.Handler) {
	var l net.Listener

	// Try to obtain parent's listener and kill him.
	if fd, err := listener(port); err != nil {
		l, err = net.Listen("tcp", port)

		if err != nil {
			log.Fatalf("failed to listen to port %s: %v", port, err)
		}
	} else {
		l = fd
		if err := killParent(); err != nil {
			log.Fatalf("failed to kill parent: %v", err)
		}
	}

	// Instead of setting WriteTimeout, we use http.TimeoutHandler to specify the
	// maximum amount of time for a handler to complete.
	handler = http.TimeoutHandler(handler, handlerTimeout, "")

	// Also limit the payload size to 1 MB.
	handler = http.MaxBytesHandler(handler, MaxBytesSize)

	// Start the web server.
	s := &http.Server{
		ReadHeaderTimeout: readTimeout,
		ReadTimeout:       readTimeout,
		Handler:           handler,
	}
	go func() {
		if err := s.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("failed to close serve: %v", err)
		}
	}()

	// Start loop which is responsible for upgrade watching.
	upgradeLoop(&l, s)
}

func upgradeLoop(l *net.Listener, s *http.Server) {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGQUIT, syscall.SIGUSR2, syscall.SIGTERM, os.Interrupt)
	for t := range sig {
		switch t {
		case syscall.SIGUSR2:
			// Fork a child and start binary upgrading.
			if err := spawnChild(); err != nil {
				log.Println(
					"Cannot perform binary upgrade, when starting process: ",
					err.Error(),
				)
				continue
			}
		case syscall.SIGQUIT, syscall.SIGTERM, os.Interrupt:
			ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
			defer cancel()

			if err := s.Shutdown(ctx); err != nil {
				log.Fatal(err)
			}

			os.Exit(0)
			return
		}
	}
}

func listener(port string) (net.Listener, error) {
	lc := net.ListenConfig{
		Control: control,
	}
	if l, err := lc.Listen(context.Background(), "tcp", port); err != nil {
		return nil, err
	} else {
		return l, nil
	}
}

// When parent process exists, send it signals, that it should perform graceful
// shutdown and stop serving new requests.
func killParent() error {
	pid, ok := os.LookupEnv("APP_PPID")
	if !ok {
		return nil
	}

	ppid, err := strconv.Atoi(pid)
	if err != nil {
		return err
	}

	if p, err := os.FindProcess(ppid); err != nil {
		return err
	} else {
		return p.Signal(syscall.SIGQUIT)
	}
}

func spawnChild() error {
	argv0, err := exec.LookPath(os.Args[0])
	if err != nil {
		return err
	}

	wd, err := os.Getwd()
	if err != nil {
		return err
	}

	files := make([]*os.File, 0)
	files = append(files, os.Stdin, os.Stdout, os.Stderr)

	ppid := os.Getpid()
	os.Setenv("APP_PPID", strconv.Itoa(ppid))

	_, err = os.StartProcess(argv0, os.Args, &os.ProcAttr{
		Dir:   wd,
		Env:   os.Environ(),
		Files: files,
		Sys:   &syscall.SysProcAttr{},
	})

	return err
}

func control(network, address string, c syscall.RawConn) error {
	var err error
	cerr := c.Control(func(fd uintptr) {
		err = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
		if err != nil {
			return
		}

		err = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
		if err != nil {
			return
		}
	})

	return errors.Join(cerr, err)
}
