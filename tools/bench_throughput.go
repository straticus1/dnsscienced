package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

var (
	target   = flag.String("target", "127.0.0.1:5354", "DNS server address")
	workers  = flag.Int("workers", 10, "Number of concurrent workers")
	domain   = flag.String("domain", "example.com.", "Domain to query")
	duration = flag.Duration("duration", 10*time.Second, "Test duration")
)

func main() {
	flag.Parse()

	log.Printf("Starting benchmark against %s with %d workers for %v", *target, *workers, *duration)

	var count uint64
	var errors uint64
	start := time.Now()
	done := make(chan struct{})

	// Pre-build packet to avoid overhead in loop
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(*domain), dns.TypeA)
	reqBytes, _ := m.Pack()

	var wg sync.WaitGroup
	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			// Use raw UDP socket for max speed
			conn, err := net.Dial("udp", *target)
			if err != nil {
				log.Printf("Dial error: %v", err)
				return
			}
			defer conn.Close()

			buf := make([]byte, 65535)

			for {
				select {
				case <-done:
					return
				default:
					// Send
					_, err := conn.Write(reqBytes)
					if err != nil {
						atomic.AddUint64(&errors, 1)
						continue
					}

					// Recv
					conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
					_, err = conn.Read(buf)
					if err != nil {
						atomic.AddUint64(&errors, 1)
						continue
					}

					atomic.AddUint64(&count, 1)
				}
			}
		}()
	}

	time.Sleep(*duration)
	close(done)
	wg.Wait()

	totalTime := time.Since(start)
	qps := float64(count) / totalTime.Seconds()

	fmt.Printf("\n--- Results ---\n")
	fmt.Printf("Total Requests: %d\n", count)
	fmt.Printf("Total Errors:   %d\n", errors)
	fmt.Printf("Duration:       %.2fs\n", totalTime.Seconds())
	fmt.Printf("QPS:            %.2f\n", qps)
}
