package cmd

import (
	"io"
	"log"

	"github.com/fsouza/go-dockerclient"
	"github.com/gorilla/websocket"
)

func runDockerExec(ws *websocket.Conn, client *docker.Client, r io.Reader, w io.Writer) (<-chan *docker.Exec, error) {
	// Setup command
	cmd := "/bin/sh"
	containerId := "32a0be471ae3"
	execConfig := docker.CreateExecOptions{
		Container:    containerId,
		AttachStdin:  true,
		AttachStdout: true,
		Tty:          true,
		Cmd:          []string{cmd},
	}
	execObj, err := client.CreateExec(execConfig)
	ret := make(chan *docker.Exec)
	if err != nil {
		log.Printf("Error creating Exec: %s\n", err.Error())
		internalError(ws, "docker", err)
		return nil, err
	}
	success := make(chan struct{})
	startConfig := docker.StartExecOptions{
		OutputStream: w,
		ErrorStream:  w,
		InputStream:  r,
		RawTerminal:  true,
		Tty:          true,
		Success:      success,
	}
	errch := make(chan error, 1)
	go func() {
		if err := client.StartExec(execObj.ID, startConfig); err != nil {
			log.Printf("Error in docker exec: %s\n", err.Error())
			errch <- err
		}
		ret <- execObj
	}()
	<-success
	close(success)
	return ret, nil
}
