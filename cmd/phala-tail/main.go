// phala-tail is the thin trusted inference entrypoint. It never constructs a
// Guard controller or makes scheduler/admission decisions.
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Phala-Network/pig-tail/internal/app/tail"
	"github.com/Phala-Network/pig-tail/internal/runtime/attestation"
)

var version = "v0.1.0"

func runCommand(args []string, serve func() error, healthcheck func() error) error {
	if len(args) == 1 {
		return serve()
	}
	if len(args) == 2 && args[1] == "healthcheck" {
		return healthcheck()
	}
	return errors.New("usage: phala-tail [healthcheck]")
}

func run() error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	token, upstream := os.Getenv("TOKEN"), os.Getenv("UPSTREAM")
	transportTLS, fingerprint, err := loadTLSConfig(os.Getenv("TLS_CERT_PATH"), os.Getenv("TLS_KEY_PATH"))
	if err != nil {
		return err
	}
	report, err := attestation.NewService(attestationConfigFromEnv(fingerprint),
		attestation.NewDstackClient(os.Getenv("DSTACK_ENDPOINT"), 3*time.Second))
	if err != nil {
		return err
	}
	handler, err := tail.New(tail.Config{Token: token, Upstream: upstream, RequestTimeout: 2 * time.Hour}, report)
	if err != nil {
		return err
	}
	defer handler.Close()
	listen := os.Getenv("LISTEN")
	if listen == "" {
		listen = defaultListenAddress
	}
	server := &http.Server{Addr: listen, Handler: handler, ReadHeaderTimeout: 30 * time.Second, TLSConfig: transportTLS}
	stopped := make(chan struct{})
	go func() {
		<-ctx.Done()
		stop, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		if err := server.Shutdown(stop); err != nil {
			_ = server.Close()
		}
		close(stopped)
	}()
	log.Printf("TAIL %s starting; native scheduler owns QoS", version)
	if transportTLS != nil {
		err = server.ListenAndServeTLS("", "")
	} else {
		err = server.ListenAndServe()
	}
	cancel()
	<-stopped
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func attestationConfigFromEnv(listenerFingerprint []byte) attestation.Config {
	// A direct TLS listener takes precedence. With external TLS termination,
	// read its public certificate per report so renewed keys are reflected.
	return attestation.Config{
		TLSCertPath:           os.Getenv("TLS_CERT_PATH"),
		TLSCertSPKISHA256:     listenerFingerprint,
		RequireNVIDIAEvidence: true,
	}
}

func main() {
	if err := runCommand(os.Args, run, runHealthcheck); err != nil {
		log.Fatal(err)
	}
}
