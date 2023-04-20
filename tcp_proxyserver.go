package main

import (
	"io"
	"log"
	"net"
	"sync"

	"github.com/SiMENhol/is105sem03/mycrypt"
)

func main() {
	var wg sync.WaitGroup
	proxyServer, err := net.Listen("tcp", "172.17.0.2:8080")
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("bundet til %s", proxyServer.Addr().String())
    wg.Add(1)
    go func() {
		defer wg.Done()
		for {
			log.Println("før proxyServer.Accept() kallet")
			conn, err := proxyServer.Accept()
			if err != nil {
				return
			}
			go func(client net.Conn) {
				defer client.Close()

				server, err := net.Dial("tcp", "172.17.0.4:8080")
                if err != nil {
					log.Println(err)
					return
				}
				defer server.Close()
				err = proxy(client, server)
				if err != nil && err != io.EOF {
					log.Println(err)
				}
			}(conn)
		}
	}()
	wg.Wait()
}

func proxy(client io.Reader, server io.Writer) error {
	clientWriter, clientIsWriter := client.(io.Writer)
	serverReader, serverIsReader := server.(io.Reader)

	if serverIsReader && clientIsWriter {
		go func() {
			_, _ = io.Copy(clientWriter, serverReader)
		}()
	}
	_, err := io.Copy(server, client)
	return err
} 
