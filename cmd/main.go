package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	libp2p "github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	host "github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/libp2p/go-libp2p/p2p/net/conngater"
	"github.com/multiformats/go-multiaddr"
)

// readSwarmKey reads the swarm.key file
func readSwarmKey(key string) ([]byte, error) {
	decodedKey, err := hex.DecodeString(key)
	if err != nil {
		return nil, fmt.Errorf("failed to decode swarm key: %w", err)
	}

	if len(decodedKey) != 32 {
		return nil, fmt.Errorf("swarm key must be 32 bytes")
	}

	return decodedKey, nil
}

func main() {
	port := flag.Int("port", 4001, "Port for the server")
	key := flag.String("key", "", "private key for host")
	peerId := flag.String("peer", "", "upstream peer")
	ip := flag.String("ip", "192.168.127.2", "upstream peer ip address")
	swarmKeyPath := flag.String("swarmKey", "swarm.key", "Path to the swarm key file")

	flag.Parse()

	if *key == "" {
		pk, id, err := GeneratePeerKey()
		if err != nil {
			log.Fatalf("Failed to create connection gater: %v", err)
		}

		log.Printf("generated key id: %s ", id)
		log.Printf("generated private key: %s ", pk)
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Read the swarm key
	swarmKey, err := readSwarmKey(*swarmKeyPath)
	if err != nil {
		log.Fatalf("Failed to load swarm key: %v", err)
	}

	// Create a connection gater for the private network
	connGater, err := conngater.NewBasicConnectionGater(nil)
	if err != nil {
		log.Fatalf("Failed to create connection gater: %v", err)
	}

	privk, err := ReadPeerKey(*key)
	if err != nil {
		log.Fatal(err)
	}

	// Create a libp2p host
	h, err := libp2p.New(
		libp2p.Identity(privk),
		libp2p.ListenAddrStrings(fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", *port)),
		libp2p.ConnectionGater(connGater),
		libp2p.EnableRelayService(), // Enable Circuit Relay v2
		libp2p.PrivateNetwork(swarmKey),
	)
	if err != nil {
		log.Fatalf("Failed to create libp2p host: %v", err)
	}
	defer h.Close()

	// Set up DHT
	kadDHT, err := dht.New(ctx, h, dht.Mode(dht.ModeServer))
	if err != nil {
		log.Fatalf("Failed to create DHT: %v", err)
	}

	// Bootstrap the DHT
	if err := kadDHT.Bootstrap(ctx); err != nil {
		log.Fatalf("Failed to bootstrap DHT: %v", err)
	}

	// Display host multiaddresses
	fmt.Println("Private DHT server is running. Connect using these addresses:")
	for _, addr := range h.Addrs() {
		fmt.Printf("%s/p2p/%s\n", addr, h.ID())
	}

	// Turn the destination into a multiaddr.
	circuitAddr := fmt.Sprintf("%s/p2p/%s/p2p-circuit/p2p/%s", h.Addrs()[0], h.ID(), *peerId)
	maddr, err := multiaddr.NewMultiaddr(circuitAddr)
	if err != nil {
		log.Println(err)
		return
	}

	// Extract the peer ID from the multiaddr.
	info, err := peer.AddrInfoFromP2pAddr(maddr)
	if err != nil {
		log.Println(err)
		return
	}

	// Add the destination's peer multiaddress in the peerstore.
	// This will be used during connection and stream creation by libp2p.
	h.Peerstore().AddAddrs(info.ID, info.Addrs, peerstore.PermanentAddrTTL)

	go runTcpServer(ctx, h, 80, *ip, *info)
	go runTcpServer(ctx, h, 443, *ip, *info)

	waitForInterrupt()
}

func waitForInterrupt() {
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)

	<-signalChan
	fmt.Println("\nReceived termination signal, shutting down...")
}

func runTcpServer(ctx context.Context, h host.Host, port uint16, ip string, info peer.AddrInfo) {
	// Start TCP listener on port 8080
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		log.Fatalf("Failed to listen on port %d: %v", port, err)
	}
	defer listener.Close()
	fmt.Printf("Listening on port %d", port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("Failed to accept connection:", err)
			continue
		}
		go handleConnection(ctx, h, conn, info, ip, "/gvisor/libp2p-tap-tcp/1.0.0", port)

	}
}

func handleConnection(ctx context.Context, h host.Host, conn net.Conn, info peer.AddrInfo, ip string, proto string, port uint16) {
	// Peek first few bytes to identify protocol
	buffer := make([]byte, 5)
	n, err := conn.Read(buffer)
	if err != nil {
		log.Printf("Failed to read data: %v", err)
		return
	}

	// Check for TLS ClientHello (HTTPS)
	if buffer[0] == 0x16 && buffer[1] == 0x03 {
		handleTLS(ctx, h, conn, info, ip, proto, port, buffer[:n])
	} else {
		handleHTTP(ctx, h, conn, info, ip, proto, port, buffer[:n])
	}
}

// Handle HTTP traffic
func handleHTTP(ctx context.Context, h host.Host, conn net.Conn, info peer.AddrInfo, ip string, proto string, port uint16, initialData []byte) {
	reader := bufio.NewReader(conn)
	buffer := append(initialData, make([]byte, 1024)...) // Read more data if needed
	n, _ := reader.Read(buffer[len(initialData):])
	buffer = buffer[:len(initialData)+n]

	host := extractHost(buffer)
	if host == "" {
		log.Println("HTTP Host header not found")
		return
	}

	upstreamAddr := resolveUpstream(host, 80)
	forwardTCP(ctx, h, conn, info, ip, proto, port, upstreamAddr, buffer)
}

// Handle HTTPS traffic
func handleTLS(ctx context.Context, h host.Host, conn net.Conn, info peer.AddrInfo, ip string, proto string, port uint16, initialData []byte) {
	sni, fullBuffer, err := extractSNI(conn, initialData)
	if err != nil {
		log.Printf("Failed to extract SNI: %v", err)
		return
	}

	upstreamAddr := resolveUpstream(sni, 443)
	forwardTCP(ctx, h, conn, info, ip, proto, port, upstreamAddr, fullBuffer)
}

// Resolve upstream server based on hostname
func resolveUpstream(host string, port int) string {
	fmt.Println("domain", host)
	switch host {
	case "example.com":
		return "localhost:8081"
	case "another.com":
		return "localhost:8082"
	default:
		return fmt.Sprintf("localhost:%d", port)
	}
}

func forwardTCP(ctx context.Context, h host.Host, conn net.Conn, info peer.AddrInfo, ip string, proto string, port uint16, address string, initialData []byte) {
	h.Connect(ctx, info)
	// Start a stream with the destination.
	// Multiaddress of the destination peer is fetched from the peerstore using 'peerId'.
	s, err := h.NewStream(context.Background(), info.ID, protocol.ID(proto))

	if err != nil {
		log.Println(err)
		return
	}
	log.Println("Established connection to destination")
	defer s.Close()
	buf := make([]byte, 2) // Assuming 4 bytes (int32)
	// Encode the integer into the buffer
	binary.BigEndian.PutUint16(buf, port)

	// Write the buffer to the stream

	addr := net.ParseIP(ip).To4() // Now addr is addressable
	_, err2 := s.Write(addr[:])
	if err2 != nil {
		log.Println("r.CreateEndpoint()")
	}
	_, err2 = s.Write(buf)
	if err2 != nil {
		log.Println("r.CreateEndpoint()")
	}
	s.Write(initialData)
	// Forward data from TCP to libp2p stream

	dest := NewBufReaderStream(conn)

	tunneling(dest, s)

}

// Extract Host header from HTTP request
func extractHost(data []byte) string {
	lines := strings.Split(string(data), "\r\n")
	for _, line := range lines {
		if strings.HasPrefix(strings.ToLower(line), "host:") {
			return strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
		}
	}
	return ""
}

func extractSNI(conn net.Conn, firstBytes []byte) (string, []byte, error) {
	buffer := append(firstBytes, make([]byte, 4096)...)
	n, err := conn.Read(buffer[len(firstBytes):])
	if err != nil {
		return "", buffer[:len(firstBytes)+n], err
	}
	buffer = buffer[:len(firstBytes)+n]

	if len(buffer) < 43 {
		return "", buffer, fmt.Errorf("invalid TLS ClientHello")
	}

	handshakeLength := int(buffer[3])<<8 | int(buffer[4])
	if len(buffer) < 5+handshakeLength {
		return "", buffer, fmt.Errorf("incomplete TLS handshake")
	}

	offset := 43
	if len(buffer) <= offset {
		return "", buffer, fmt.Errorf("invalid offset")
	}

	sessionIDLen := int(buffer[offset])
	offset += 1 + sessionIDLen

	if len(buffer) <= offset+2 {
		return "", buffer, fmt.Errorf("invalid cipher suites length")
	}
	cipherSuitesLen := int(binary.BigEndian.Uint16(buffer[offset : offset+2]))
	offset += 2 + cipherSuitesLen

	if len(buffer) <= offset {
		return "", buffer, fmt.Errorf("invalid compression methods")
	}
	compressionMethodsLen := int(buffer[offset])
	offset += 1 + compressionMethodsLen

	if len(buffer) < offset+2 {
		return "", buffer, fmt.Errorf("no extensions found")
	}
	extensionsLength := int(binary.BigEndian.Uint16(buffer[offset : offset+2]))
	offset += 2

	endExtensions := offset + extensionsLength
	for offset+4 <= endExtensions {
		extensionType := binary.BigEndian.Uint16(buffer[offset : offset+2])
		extensionLen := int(binary.BigEndian.Uint16(buffer[offset+2 : offset+4]))
		offset += 4

		if extensionType == 0x0000 {
			if offset+extensionLen > len(buffer) {
				return "", buffer, fmt.Errorf("invalid SNI extension length")
			}
			sniListLen := int(binary.BigEndian.Uint16(buffer[offset : offset+2]))
			offset += 2
			if offset+sniListLen > len(buffer) {
				return "", buffer, fmt.Errorf("invalid SNI list length")
			}

			if sniListLen < 3 {
				return "", buffer, fmt.Errorf("invalid SNI entry")
			}
			sniType := buffer[offset]
			sniLen := int(binary.BigEndian.Uint16(buffer[offset+1 : offset+3]))
			offset += 3

			if sniType != 0x00 || offset+sniLen > len(buffer) {
				return "", buffer, fmt.Errorf("invalid SNI type or length")
			}

			return string(buffer[offset : offset+sniLen]), buffer, nil
		}

		offset += extensionLen
	}

	return "", buffer, fmt.Errorf("SNI not found")
}
