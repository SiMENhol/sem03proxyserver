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

				server, err := net.Dial("tcp", "127.0.0.1:8080")
				if err != nil {
					log.Println(err)
					return
				}
				defer server.Close()

				// Leser kryptert melding fra klienten
				buf := make([]byte, 1024)
				n, err := client.Read(buf)
				if err != nil {
					log.Println(err)
					return
				}
				kryptertMelding := buf[:n]

				// Dekrypterer meldingen fra klienten
				dekryptertMelding := mycrypt.Krypter([]rune(string(kryptertMelding)), mycrypt.ALF_SEM03, len(mycrypt.ALF_SEM03)-4)
				log.Println("Dekryptert melding fra klienten: ", string(dekryptertMelding))

				// Krypterer meldingen og sender den til serveren
				kryptertMeldingTilServer := mycrypt.Krypter([]rune(string(dekryptertMelding)), mycrypt.ALF_SEM03, len(mycrypt.ALF_SEM03)+4)
				_, err = server.Write([]byte(string(kryptertMeldingTilServer)))
				if err != nil {
					log.Println(err)
					return
				}

				err = proxy(client, server)
				if err != nil && err != io.EOF {
					log.Println(err)
				}

				// Leser kryptert svar fra serveren
				n, err = server.Read(buf)
				if err != nil {
					log.Println(err)
					return
				}
				kryptertSvar := buf[:n]

				// Dekrypterer svar fra serveren og sender det tilbake til klienten
				dekryptertSvar := mycrypt.Krypter([]rune(string(kryptertSvar)), mycrypt.ALF_SEM03, len(mycrypt.ALF_SEM03)-4)
				log.Println("Dekryptert svar fra serveren: ", string(dekryptertSvar))

				_, err = client.Write([]byte(string(dekryptertSvar)))
				if err != nil {
					log.Println(err)
					return
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
