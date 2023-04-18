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
	proxyServer, err := net.Listen("tcp", "172.17.0.4:8080")
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

				server, err := net.Dial("tcp", "172.17.0.2:8080")
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

/*
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
*/

func proxy(client io.Reader, server io.Writer) error {
	clientWriter, clientIsWriter := client.(io.Writer)
	serverReader, serverIsReader := server.(io.Reader)

	if serverIsReader && clientIsWriter {
		go func() {
			buf := make([]byte, 1024)
			for {
				n, err := serverReader.Read(buf)
				if err != nil {
					if err != io.EOF {
						log.Println(err)
					}
					return // fra for-løkke
				}

				// Dekrypterer meldingen fra serveren
				dekryptertMelding := mycrypt.Krypter([]rune(string(buf[:n])), mycrypt.ALF_SEM03, len(mycrypt.ALF_SEM03)-4)
				log.Println("Dekryptert melding fra server: ", string(dekryptertMelding))

				// Sender meldingen til klienten etter kryptering
				kryptertMelding := mycrypt.Krypter([]rune(string(dekryptertMelding)), mycrypt.ALF_SEM03, 4)
				_, err = clientWriter.Write([]byte(string(kryptertMelding)))
				if err != nil {
					log.Println(err)
					return // fra for-løkke
				}
			}
		}()
	}

	buf := make([]byte, 1024)
	for {
		n, err := client.Read(buf)
		if err != nil {
			if err != io.EOF {
				log.Println(err)
			}
			return err
		}

		// Krypterer meldingen fra klienten
		dekryptertMelding := mycrypt.Krypter([]rune(string(buf[:n])), mycrypt.ALF_SEM03, 4)
		log.Println("dekryptert melding fra klient: ", string(dekryptertMelding))

		_, err = server.Write([]byte(string(dekryptertMelding)))
		if err != nil {
			log.Println(err)
			return err
		}
	}
}
