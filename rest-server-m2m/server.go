package main

import (
	"fmt"
	log "log/slog"
	"net/http"
	"os"

	"rest-server-m2m/internal/auth"

	"github.com/valkey-io/valkey-go"
)

func main() {
	issuer := os.Getenv("JWT_ISSUER")
	if issuer == "" {
		log.Error("JWT_ISSUER must be set")
		os.Exit(1)
	}

	scope := os.Getenv("JWT_REQUIRED_SCOPE")
	if scope == "" {
		log.Error("JWT_REQUIRED_SCOPE must be set")
		os.Exit(1)
	}

	valkeyServerAddr := os.Getenv("VALKEY_SERVER_ADDRESS")
	if valkeyServerAddr == "" {
		valkeyServerAddr = "localhost:6379"
	}

	valkeyClient, err := valkey.NewClient(valkey.ClientOption{InitAddress: []string{valkeyServerAddr}})
	defer valkeyClient.Close()
	if err != nil {
		log.Error("unable to load valkey client", "error", err)
		os.Exit(1)
	}

	a := auth.NewAuth(valkeyClient, scope, issuer)

	http.HandleFunc("/public", publicHandler)
	http.Handle("/private", a.WithAuth(http.HandlerFunc(privateHandler)))

	port := "8080"
	log.Info("Server running", "port", port)
	if err = http.ListenAndServe(fmt.Sprintf(":%s", port), nil); err != nil {
		log.Error("Problem with the HTTP server", "error", err)
	}

}

func publicHandler(w http.ResponseWriter, _ *http.Request) {
	_, err := fmt.Fprintln(w, "This is a public endpoint. No auth is required.")
	if err != nil {
		log.Error("Problem writing the HTTP response", "error", err)
	}
}

func privateHandler(w http.ResponseWriter, _ *http.Request) {
	_, err := fmt.Fprintln(w, "This is a protected endpoint. JWT token is valid.")
	if err != nil {
		log.Error("Problem writing the HTTP response", "error", err)
	}
}
