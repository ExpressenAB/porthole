// Copyright © 2016 Porthole authors & AB Kvällstidningen Expressen <infra@expressen.se>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"bufio"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/cldmnky/vault-jwt-go"
	"github.com/dgrijalva/jwt-go"
	jwtRequest "github.com/dgrijalva/jwt-go/request"
	"github.com/fsouza/go-dockerclient"
	"github.com/gorilla/context"
	"github.com/gorilla/websocket"
	vaultapi "github.com/hashicorp/vault/api"
	"github.com/justinas/alice" // chained middleware
	"github.com/mitchellh/mapstructure"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	addr       string
	useTls     bool
	tlsCert    string
	tlsKey     string
	auth       string
	pskFile    string
	vaultAddr  string
	vaultToken string
	vaultPath  string

	upgrader = websocket.Upgrader{
		CheckOrigin:     func(r *http.Request) bool { return true },
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
	}
	vaultConfig = vaultapi.DefaultConfig()
	pskList     = viper.New()
)

const (
	// Time allowed to write a message to the peer.
	writeWait = 10 * time.Second
	// Maximum message size allowed from peer.
	maxMessageSize = 8192
	// Time allowed to read the next pong message from the peer.
	pongWait = 60 * time.Second
	// Send pings to peer with this period. Must be less than pongWait.
	pingPeriod = (pongWait * 9) / 10
	// Time to wait before force close on connection.
	closeGracePeriod = 10 * time.Second
	// serve porthole ws from
	portholePath = "/exec"
)

type PortholeClaims struct {
	ContainerId string   `json:"containerId"`
	Cmd         []string `json:"cmd"`
	Tty         bool     `json:"tty"`
	jwt.StandardClaims
}

// serveCmd represents the serve command
var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start a porthole server",
	Long: `Start a porthole server:
Exmple:
	porthole serve --auth psk --addr 10.0.0.1 --port 443 --tls-cert /etc/pki/mycert.crt
	porthole serve --auth vault --vault-addr http://10.0.0.2:8200 --vault-token mytoken --vault-path porthole --addr 10.0.0.1:4443 --tls --tls-cert /etc/pki/mycert.crt
that´s it!`,
	Run: serve,
}

func init() {
	RootCmd.AddCommand(serveCmd)
	serveCmd.PersistentFlags().StringVar(&addr, "addr", "127.0.0.1:8888", "porthole listen address")
	serveCmd.PersistentFlags().BoolVar(&useTls, "tls", true, "Enable tls")
	serveCmd.PersistentFlags().StringVar(&tlsCert, "tls-cert", "${HOME}/porthole.crt", "path to porthole tls certificate")
	serveCmd.PersistentFlags().StringVar(&tlsKey, "tls-key", "${HOME}/porthole.key", "path to porthole tls key")
	serveCmd.PersistentFlags().StringVar(&auth, "auth", "psk", "jwt auth provider, must be one of (hmac/vault)")
	serveCmd.PersistentFlags().StringVar(&pskFile, "psk-file", "${HOME}/porthole-psk", "yaml file of psk: [<accesskeys>:<secretkeys>]")
	serveCmd.PersistentFlags().StringVar(&vaultAddr, "vault-addr", "http://127.0.0.1:8200", "vault address")
	serveCmd.PersistentFlags().StringVar(&vaultToken, "vault-token", "myroot", "vault token")
	serveCmd.PersistentFlags().StringVar(&vaultPath, "vault-path", "porthole", "vault path, will be appended to /transit/hmac/")
	viper.SetEnvPrefix("porthole")
	//viper.BindPFlag("addr2", serveCmd.Flags().Lookup("addr2"))
	//viper.BindEnv("addr2")
	pskList.SetConfigName("psk-file")
	pskList.AddConfigPath(pskFile)
}

func serve(cmd *cobra.Command, args []string) {
	chain := alice.New(jwtMiddleware)

	http.HandleFunc("/", serveRoot)
	http.Handle(portholePath, chain.ThenFunc(servePortholeWs))

	log.Fatal(http.ListenAndServe(addr, nil))
}

func internalError(ws *websocket.Conn, msg string, err error) {
	log.Println(msg, err)
	ws.WriteMessage(websocket.TextMessage, []byte("Internal server error."))
}

func jwtMiddleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		vaultConfig.Address = vaultAddr
		config := vault_jwt.Config{
			vaultConfig,
			vaultPath,
			vaultToken,
			false,
		}
		token, err := jwtRequest.ParseFromRequest(r, jwtRequest.AuthorizationHeaderExtractor, func(token *jwt.Token) (interface{}, error) {
			if ok := strings.ToLower(token.Method.Alg()) == strings.ToLower(auth); !ok {
				log.Printf("Got alg: %s", token.Method.Alg())
				return nil, errors.New("unexpected signing alg")
			}
			if ok := token.Claims.(jwt.MapClaims)["sub"] != nil; !ok {
				log.Println("Missing subject in claim")
				return nil, errors.New("missing subject in claim")
			}
			return config, nil
		})
		if err != nil {
			log.Printf("jwt error: %s", err.Error())
			http.Error(w, "Not authorized", 401)
			return
		}
		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			var pc PortholeClaims
			if err := mapstructure.Decode(claims, &pc); err != nil {
				log.Printf("decode error: %s", err.Error())
				http.Error(w, "Not authorized", 401)
				return
			}
			log.Printf("Claims: %v", pc)
			context.Set(r, "claims", pc)
		} else {
			log.Printf("jwt error: %s", err.Error())
			http.Error(w, "Not authorized", 401)
			return
		}
		h.ServeHTTP(w, r)
	})
}

func serveRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.Error(w, "Not found", 404)
	}
	http.Redirect(w, r, portholePath, http.StatusPermanentRedirect)
}

func servePortholeWs(w http.ResponseWriter, r *http.Request) {
	log.Printf("New client connected: %s", r.RemoteAddr)
	log.Printf("%s", context.Get(r, "claims"))
	// Setup ws
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Connection upgrade failed: %s\n", err.Error())
		return
	}
	defer ws.Close()

	outr, outw, _ := os.Pipe()
	defer outr.Close()
	defer outw.Close()

	inr, inw, _ := os.Pipe()
	defer inr.Close()
	defer inw.Close()

	// Run docker exec
	endpoint := "unix:///var/run/docker.sock"
	client, err := docker.NewClient(endpoint)
	if err != nil {
		log.Printf("Error creating docker client: %s\n", err.Error())
		internalError(ws, "docker", err)
		return
	}
	ret, err := runDockerExec(ws, client, inr, outw)

	stdoutDone := make(chan struct{})
	go pumpStdout(ws, outr, stdoutDone)
	go ping(ws, stdoutDone)
	// maybe docker exec should be blockinh here, not pumpStdin.
	pumpStdin(ws, inw)
	inw.Close()
	inr.Close()
	execObj := <-ret
	select {
	case <-stdoutDone:
	case <-time.After(time.Second):
		log.Println("stdout closed")
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		count := 0
		for {
			inspect, err2 := client.InspectExec(execObj.ID)
			if err2 != nil {
				return
			}
			if !inspect.Running {
				if inspect.ExitCode != 0 {
					log.Printf("container not running\n")
				}
				break
			}

			count++
			if count == 5 {
				log.Printf("Exec session %s in container terminated but process still running!\n", execObj.ID)
				break
			}

			<-ticker.C
		}
		<-stdoutDone
	}
}

func pumpStdout(ws *websocket.Conn, r io.Reader, done chan struct{}) {
	defer func() {
	}()
	s := bufio.NewScanner(r)
	for s.Scan() {
		ws.SetWriteDeadline(time.Now().Add(writeWait))
		if err := ws.WriteMessage(websocket.TextMessage, s.Bytes()); err != nil {
			ws.Close()
			break
		}
	}
	if s.Err() != nil {
		log.Println("scan:", s.Err())
	}
	close(done)

	ws.SetWriteDeadline(time.Now().Add(writeWait))
	ws.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
	time.Sleep(closeGracePeriod)
	ws.Close()
}

func pumpStdin(ws *websocket.Conn, w io.Writer) {
	defer ws.Close()
	ws.SetReadLimit(maxMessageSize)
	ws.SetReadDeadline(time.Now().Add(pongWait))
	ws.SetPongHandler(func(string) error { ws.SetReadDeadline(time.Now().Add(pongWait)); return nil })
	for {
		_, message, err := ws.ReadMessage()
		log.Printf("stdin: message: %s", message)
		if err != nil {
			log.Printf("error: %s", err.Error())
			break
		}
		message = append(message, '\n')
		if _, err := w.Write(message); err != nil {
			break
		}
	}
}

func ping(ws *websocket.Conn, done chan struct{}) {
	ticker := time.NewTicker(pingPeriod)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if err := ws.WriteControl(websocket.PingMessage, []byte{}, time.Now().Add(writeWait)); err != nil {
				log.Println("ping:", err)
			}
		case <-done:
			return
		}
	}
}
