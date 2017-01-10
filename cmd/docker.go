package cmd

import (
	"io"
	"log"

	"github.com/fsouza/go-dockerclient"
)

func runDockerExec(client *docker.Client, c string, r io.Reader, w io.Writer, command []string, tty bool, success chan struct{}) (*docker.Exec, error) {
	// Setup command

	//cmd := "/bin/bash"
	containerID := c
	execConfig := docker.CreateExecOptions{
		Container:    containerID,
		AttachStdin:  true,
		AttachStdout: true,
		Tty:          tty,
		Cmd:          command,
	}
	execObj, err := client.CreateExec(execConfig)
	if err != nil {
		log.Printf("Error creating Exec: %s\n", err.Error())
		return nil, err
	}
	//success := make(chan struct{})
	startConfig := docker.StartExecOptions{
		OutputStream: w,
		ErrorStream:  w,
		InputStream:  r,
		RawTerminal:  tty,
		Tty:          tty,
		//Success:      success,
	}
	log.Println("Starting docker exec")
	// if err := client.StartExec(execObj.ID, startConfig); err != nil {
	// 	log.Printf("Error in docker exec: %s\n", err.Error())
	// }
	go func() {
		if err := client.StartExec(execObj.ID, startConfig); err != nil {
			log.Printf("Error in docker exec: %s\n", err.Error())
		}
	}()
	//<-success
	log.Println("Docker exec started")
	return execObj, nil
}
