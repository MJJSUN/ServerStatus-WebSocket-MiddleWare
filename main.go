package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

var (
	wsPort    = flag.Int("ws-port", 8080, "WebSocket server port")
	tcpHost   = flag.String("tcp-host", "localhost", "Target TCP host")
	tcpPort   = flag.Int("tcp-port", 35601, "Target TCP port")
	logFile   = flag.String("log", "middleware.log", "Log file path")
	verbose   = flag.Bool("verbose", false, "Enable verbose logging")
	useTLS    = flag.Bool("tls", false, "Enable TLS for WebSocket")
	certFile  = flag.String("cert", "cert.pem", "TLS certificate file")
	keyFile   = flag.String("key", "key.pem", "TLS private key file")
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow all origins
	},
	Subprotocols: []string{"server-status"}, // 添加自定义协议
}

type ConnectionPair struct {
	wsConn        *websocket.Conn
	tcpConn       net.Conn
	clientIP      string
	authenticated bool
	lastActive    time.Time
}

func main() {
	flag.Parse()
	
	// Setup logging
	logFile, err := os.OpenFile(*logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}
	defer logFile.Close()
	log.SetOutput(logFile)
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	
	log.Println("Starting WebSocket to TCP middleware")
	log.Printf("WebSocket server on port: %d", *wsPort)
	log.Printf("Forwarding to TCP server: %s:%d", *tcpHost, *tcpPort)
	
	// Connection tracking
	connections := make(map[string]*ConnectionPair)
	var connMutex sync.Mutex
	
	// WebSocket handler
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		clientIP := getClientIP(r)
		log.Printf("New WebSocket connection from: %s", clientIP)
		
		// Upgrade to WebSocket
		wsConn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Printf("WebSocket upgrade failed: %v", err)
			return
		}
		defer wsConn.Close()
		
		// Connect to target TCP server
		tcpAddr := fmt.Sprintf("%s:%d", *tcpHost, *tcpPort)
		tcpConn, err := net.DialTimeout("tcp", tcpAddr, 5*time.Second)
		if err != nil {
			log.Printf("TCP connection failed to %s: %v", tcpAddr, err)
			wsConn.WriteMessage(websocket.CloseMessage, []byte(err.Error()))
			return
		}
		defer tcpConn.Close()
		
		// Create connection pair
		pair := &ConnectionPair{
			wsConn:        wsConn,
			tcpConn:       tcpConn,
			clientIP:      clientIP,
			authenticated: false,
			lastActive:    time.Now(),
		}
		
		// Register connection
		connMutex.Lock()
		connections[clientIP] = pair
		connMutex.Unlock()
		
		// Remove connection when done
		defer func() {
			connMutex.Lock()
			delete(connections, clientIP)
			connMutex.Unlock()
			log.Printf("Connection closed: %s", clientIP)
		}()
		
		// Start authentication process
		go pair.startAuthentication()
		
		// Start bidirectional forwarding
		var wg sync.WaitGroup
		wg.Add(2)
		
		// WebSocket -> TCP
		go func() {
			defer wg.Done()
			for {
				// Read message from WebSocket
				messageType, message, err := wsConn.ReadMessage()
				if err != nil {
					if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
						log.Printf("WebSocket read error from %s: %v", clientIP, err)
					}
					break
				}
				
				// Update last active time
				pair.lastActive = time.Now()
				
				if *verbose {
					log.Printf("WS->TCP [%s]: %s", clientIP, string(message))
				}
				
				// Check if we're in authentication phase
				if !pair.authenticated {
					// Check if this is authentication data
					if strings.Contains(string(message), ":") {
						parts := strings.SplitN(string(message), ":", 2)
						if len(parts) == 2 {
							user := strings.TrimSpace(parts[0])
							log.Printf("Forwarding authentication for %s: user=%s", clientIP, user)
						}
					}
					
					// Forward to TCP server
					_, err = tcpConn.Write(message)
					if err != nil {
						log.Printf("TCP write error to %s: %v", tcpAddr, err)
						break
					}
					continue
				}
				
				// If authenticated, only forward data messages
				if messageType == websocket.TextMessage {
					_, err = tcpConn.Write(message)
					if err != nil {
						log.Printf("TCP write error to %s: %v", tcpAddr, err)
						break
					}
				}
			}
		}()
		
		// TCP -> WebSocket
		go func() {
			defer wg.Done()
			reader := bufio.NewReader(tcpConn)
			for {
				line, err := reader.ReadBytes('\n')
				if err != nil {
					log.Printf("TCP read error from %s: %v", tcpAddr, err)
					break
				}
				
				// Update last active time
				pair.lastActive = time.Now()
				
				if *verbose {
					log.Printf("TCP->WS [%s]: %s", clientIP, string(line))
				}
				
				// Check for authentication responses
				if !pair.authenticated {
					if bytes.Contains(line, []byte("Authentication successful")) {
						pair.authenticated = true
						log.Printf("Client %s authenticated successfully", clientIP)
					} else if bytes.Contains(line, []byte("Authentication failed")) {
						log.Printf("Authentication failed for %s", clientIP)
					}
				}
				
				// Forward to WebSocket client
				err = wsConn.WriteMessage(websocket.TextMessage, line)
				if err != nil {
					log.Printf("WebSocket write error to %s: %v", clientIP, err)
					break
				}
			}
		}()
		
		// Start heartbeat
		go pair.startHeartbeat()
		
		wg.Wait()
	})
	
	// Start status server
	go func() {
		statusPort := *wsPort + 1
		http.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
			connMutex.Lock()
			defer connMutex.Unlock()
			
			status := struct {
				ActiveConnections int      `json:"active_connections"`
				ConnectedClients  []string `json:"connected_clients"`
				Authenticated     int      `json:"authenticated"`
			}{
				ActiveConnections: len(connections),
				ConnectedClients:  make([]string, 0, len(connections)),
				Authenticated:     0,
			}
			
			for _, pair := range connections {
				status.ConnectedClients = append(status.ConnectedClients, pair.clientIP)
				if pair.authenticated {
					status.Authenticated++
				}
			}
			
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(status)
		})
		
		log.Printf("Status server running on :%d/status", statusPort)
		http.ListenAndServe(fmt.Sprintf(":%d", statusPort), nil)
	}()
	
	// Start connection monitor
	go func() {
		for {
			time.Sleep(30 * time.Second)
			connMutex.Lock()
			for ip, pair := range connections {
				if time.Since(pair.lastActive) > 90*time.Second {
					log.Printf("Connection %s timed out", ip)
					pair.wsConn.Close()
					pair.tcpConn.Close()
					delete(connections, ip)
				}
			}
			connMutex.Unlock()
		}
	}()
	
	// Start WebSocket server
	addr := fmt.Sprintf(":%d", *wsPort)
	log.Printf("WebSocket server starting on %s", addr)
	
	if *useTLS {
		log.Printf("Using TLS with cert: %s, key: %s", *certFile, *keyFile)
		err = http.ListenAndServeTLS(addr, *certFile, *keyFile, nil)
	} else {
		err = http.ListenAndServe(addr, nil)
	}
	
	if err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

func (p *ConnectionPair) startAuthentication() {
	// Wait for initial data from TCP server
	reader := bufio.NewReader(p.tcpConn)
	
	// Set timeout for authentication
	timeout := time.After(15 * time.Second)
	
	for {
		select {
		case <-timeout:
			if !p.authenticated {
				log.Printf("Authentication timeout for %s", p.clientIP)
				p.wsConn.WriteMessage(websocket.CloseMessage, 
					websocket.FormatCloseMessage(websocket.ClosePolicyViolation, "Authentication timeout"))
				p.wsConn.Close()
				p.tcpConn.Close()
			}
			return
			
		default:
			// Check if TCP server has data
			p.tcpConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			line, err := reader.ReadBytes('\n')
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					// No data yet, continue waiting
					continue
				}
				log.Printf("TCP read error during auth: %v", err)
				return
			}
			
			// Forward to WebSocket client
			if *verbose {
				log.Printf("TCP->WS [auth] [%s]: %s", p.clientIP, string(line))
			}
			
			err = p.wsConn.WriteMessage(websocket.TextMessage, line)
			if err != nil {
				log.Printf("WebSocket write error during auth: %v", err)
				return
			}
			
			// Check if this is an authentication request
			if bytes.Contains(line, []byte("Authentication required")) {
				log.Printf("Authentication required for %s", p.clientIP)
				// We've forwarded the auth request, now wait for client response
				return
			}
			
			// Check if authentication succeeded
			if bytes.Contains(line, []byte("Authentication successful")) {
				p.authenticated = true
				log.Printf("Client %s authenticated successfully", p.clientIP)
				return
			}
		}
	}
}

func (p *ConnectionPair) startHeartbeat() {
	ticker := time.NewTicker(25 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			if time.Since(p.lastActive) > 60*time.Second {
				log.Printf("Heartbeat timeout for %s", p.clientIP)
				p.wsConn.Close()
				p.tcpConn.Close()
				return
			}
			
			if err := p.wsConn.WriteMessage(websocket.PingMessage, nil); err != nil {
				log.Printf("Heartbeat ping failed for %s: %v", p.clientIP, err)
				return
			}
			
			if *verbose {
				log.Printf("Sent ping to %s", p.clientIP)
			}
		}
	}
}

func getClientIP(r *http.Request) string {
	// Get client IP from X-Forwarded-For if behind proxy
	ip := r.Header.Get("X-Forwarded-For")
	if ip == "" {
		ip = r.RemoteAddr
	}
	return ip
}