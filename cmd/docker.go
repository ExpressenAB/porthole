package cmd

import (
	"io"
	"log"

	"github.com/fsouza/go-dockerclient"
	"github.com/gorilla/websocket"
)

func runDockerExec(ws *websocket.Conn, client *docker.Client, r io.Reader, w io.Writer, command []string, tty bool) (*docker.Exec, error) {
	// Setup command

	//cmd := "/bin/bash"
	containerId := "6d90028013a3"
	execConfig := docker.CreateExecOptions{
		Container:    containerId,
		AttachStdin:  true,
		AttachStdout: true,
		Tty:          tty,
		Cmd:          command,
	}
	execObj, err := client.CreateExec(execConfig)
	if err != nil {
		log.Printf("Error creating Exec: %s\n", err.Error())
		internalError(ws, "docker", err)
		return nil, err
	}
	//success := make(chan struct{})
	startConfig := docker.StartExecOptions{
		OutputStream: w,
		ErrorStream:  w,
		InputStream:  r,
		RawTerminal:  true,
		Tty:          true,
		//Success:      success,
	}
	log.Println("Starting docker exec")
	if err := client.StartExec(execObj.ID, startConfig); err != nil {
		log.Printf("Error in docker exec: %s\n", err.Error())
		return nil, err
	}
	return execObj, nil
}
