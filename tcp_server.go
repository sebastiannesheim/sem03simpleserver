package main

import (
	"io"
	"log"
	"net"
	"strings"
	"sync"

	"github.com/sebastiannesheim/Minyr/yr"
	"github.com/sebastiannesheim/is105sem03/mycrypt"
)

func main() {
	var wg sync.WaitGroup

	server, err := net.Listen("tcp", "172.17.0.3:8080")
	if err != nil {
		log.Fatal(err)
	}
	defer server.Close()

	log.Printf("bundet til %s", server.Addr().String())

	wg.Add(1)
	go func() {
		defer wg.Done()

		for {
			log.Println("før server.Accept() kallet")

			conn, err := server.Accept()
			if err != nil {
				log.Println(err)
				continue
			}

			wg.Add(1)
			go func(c net.Conn) {
				defer wg.Done()
				defer conn.Close()

				for {
					buf := make([]byte, 2048)
					n, err := c.Read(buf)
					if err != nil {
						if err != io.EOF {
							log.Println(err)
						}
						return
					}

					dekryptertMelding := mycrypt.Krypter([]rune(string(buf[:n])), mycrypt.ALF_SEM03, len(mycrypt.ALF_SEM03)-4) //Dekryptere meldingen
					log.Println("Dekrypter melding: ", string(dekryptertMelding))                                              //Printer den dekrypte meldingen

					msgString := string(dekryptertMelding) //Meldingen konverteres til string og lagres i msgString

					switch msgString {
					case "ping":
						kryptertMelding := mycrypt.Krypter([]rune("pong"), mycrypt.ALF_SEM03, -4) //Dette krypterer til pong
						log.Println("Kryptert melding: ", string(kryptertMelding))                //Printer den krypterte meldingen
						_, err = c.Write([]byte(string(kryptertMelding)))                         //Den krypterte meldingen blir sendt tilbake til klienten

					default:
						if strings.HasPrefix(msgString, "Kjevik") { //Hvis input begynner med Kjevik
							newString, err := yr.CelsiusToFahrenheitLine("Kjevik;SN39040;18.03.2022 01:50;6") //Dette sender til yr.CelsiusToFahrenheitLine() for å få en streng som viser en temperaturkonvertering fra Celsius til Fahrenheit
							if err != nil {
								log.Fatal(err)
							}

							kryptertMelding := mycrypt.Krypter([]rune(newString), mycrypt.ALF_SEM03, len(mycrypt.ALF_SEM03)-4) // Dette krypterer newString
							_, err = conn.Write([]byte(string(kryptertMelding)))                                               //Den krypterte meldingen sendes tilbake til klient
						} else {
							kryptertMelding := mycrypt.Krypter([]rune(string(buf[:n])), mycrypt.ALF_SEM03, len(mycrypt.ALF_SEM03)-4) // Dette krypterer meldingen
							_, err = c.Write([]byte(string(kryptertMelding)))                                                        //Hvis ikke ping eller Kjevik sendes input tilbake som kryptert

						}
					}

					if err != nil {
						if err != io.EOF {
							log.Println(err)
						}
						return
					}
				}
			}(conn)
		}
	}()

	wg.Wait()
}
