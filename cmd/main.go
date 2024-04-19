package main

import (
	"GO_galletaApp_backend/internal"
	"GO_galletaApp_backend/modules"
	"context"
	"crypto/tls"
	"fmt"
	"github.com/gin-contrib/secure"
	"github.com/gin-gonic/gin"
	"github.com/jpengineer/logger"
	"github.com/patrickmn/go-cache"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Documentation: https://gin-gonic.com/docs/quickstart/

const (
	version     string = "v0.1.0"
	GET         string = "GET"
	POST        string = "POST"
	PUT         string = "PUT"
	DELETE      string = "DELETE"
	OPTIONS     string = "OPTIONS"
	certificate string = "./certificates/certificate.pem"
	key         string = "./certificates/private_key.pem"
)

var (
	_log        *logger.Log
	_logDB      *logger.Log
	config      modules.Config
	headerCheck bool
	headerValue string
	err         error
)

func main() {
	// LOAD CONFIG
	config, err = modules.LoadConfig()
	if err != nil {
		panic(fmt.Sprintf("[ERROR] An error occurred while trying to load the server configuration. %v", err))
	}

	// LOGGER
	_log = modules.InitLog(config.Server.Name, config.Log.Path, config.Log.Level, config.Log.MaxSizeMb, config.Log.MaxBackup)
	_logDB = modules.InitLogDB(config.Server.Name, config.Log.Path, config.Log.Level, config.Log.MaxSizeMb, config.Log.MaxBackup)
	defer _log.Close()
	defer _logDB.Close()

	pid := os.Getpid()
	fmt.Printf("Welcome Back! - %v Server %v  - PID %v \n", config.Server.Name, version, pid)
	_log.Info("Welcome Back! - %v Server %v  - PID %v", config.Server.Name, version, pid)

	// GET PUBLIC IP
	resp, err := http.Get("https://ifconfig.me/ip")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer resp.Body.Close()

	publicIPBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		_log.Error(err)
	}
	publicIP := string(publicIPBytes)

	// GET LOCAL IP
	var localIP string
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		_log.Error(err)
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil && ipnet.IP.IsPrivate() {
				localIP = ipnet.IP.String()
				break
			}
		}
	}

	fmt.Printf("Starting server at https://%s:%d\n", localIP, config.Server.Port)

	_log.Info("Dev mode: %t | Server Name: %s | Server port: %d | Local IP: %s | Public IP: %s | Header key: %t",
		config.Server.Dev, config.Server.Name, config.Server.Port, localIP, publicIP, config.Server.HeaderKey)

	// UPDATE HEADER CHECK
	headerCheck = config.Server.HeaderKey
	headerValue = config.Server.HeaderValue

	// START GIN FRAMEWORK
	router := gin.Default()

	// SERVER MODE
	if config.Server.Dev {
		_log.Warn("Running in 'dev' mode. Switch 'dev = false' in config file to production.")
		gin.SetMode(gin.DebugMode)
	} else {
		_log.Info("Running in 'Production' mode.")
		gin.SetMode(gin.ReleaseMode)
	}

	serverPort := strconv.Itoa(config.Server.Port)
	router.Use(secure.New(secure.Config{
		AllowedHosts: []string{
			"localhost:" + serverPort,
			"127.0.0.1:" + serverPort,
			localIP + ":" + serverPort,
			publicIP + ":" + serverPort,
		},
		SSLRedirect: true, // True: will automatically redirect HTTP requests to HTTPS.
		SSLHost:     "127.0.0.1:" + strconv.Itoa(config.Server.Port),
		//SSLProxyHeaders:       map[string]string{"X-Forwarded-Proto": "https"}, // [NO applied to mobile app] Defines a header map to be used when the server is behind a reverse proxy. In this example, "X-Forwarded-Proto" is configured to indicate that the original request was made through HTTPS// Specify the host name that will be used in the redirection to HTTPS
		//STSSeconds:            315360000,                                       // [NO applied to mobile app] Set the Strict-Transport-Security (HSTS) header in the HTTP response. This header tells the browser that it should only connect to the server via HTTPS for a specific period of time, in seconds (10 years = 315360000)
		//STSIncludeSubdomains:  true,                                            // [NO applied to mobile app] When set to true, it indicates that the HSTS policy also applies to all subdomains of the main domain
		//FrameDeny:             true,                                            // [NO applied to mobile app] Configure the X-Frame-Options header to deny the loading of the page in an iframe, which protects against "clickjacking" attacks
		//ContentTypeNosniff:    true,                                            // [NO applied to mobile app] Configure the X-Content-Type-Options header to prevent the browser from guessing the type of content, which reduces the risk of certain types of attacks
		//BrowserXssFilter:      true,                                            // [NO applied to mobile app] Enables the built-in browser filter against Cross-Site Scripting (XSS) attacks
		//ContentSecurityPolicy: "default-src 'self'",                            // [NO applied to mobile app] Configure the content security policy (CSP) that specifies the sources from which resources can be loaded on your website
		//IENoOpen:              true,                                            // [NO applied to mobile app] Set the X-Download-Options header to prevent Internet Explorer from running downloads in the HTML context
		//ReferrerPolicy:        "strict-origin-when-cross-origin",               // [NO applied to mobile app] Configure the referrer policy that controls what referrer information is included in HTTP requests. "strict-origin-when-cross-origin" indicates that the complete referrer is sent only for requests from the same origin
	}))

	// START DB CONNECTION
	dbInstance := modules.NewDBInstance()

	if err := dbInstance.InitDB(&config, _logDB); err != nil {
		_log.Error("An error occurred while establishing the connection to the database.")
	}
	defer dbInstance.Close()

	// CREATE SERVER CACHE
	ServerCache := cache.New(time.Duration(config.Cache.ExpirationTime)*time.Minute,
		time.Duration(config.Cache.CleanUpInterval)*time.Minute)
	_log.Info("The server cache has been configured with an expiration time of %v minutes and %v minutes "+
		"to clean up interval.", config.Cache.ExpirationTime, config.Cache.CleanUpInterval)

	// APPLY MIDDLEWARE TO GIN
	router.Use(dbMiddleware(dbInstance, _logDB))
	router.Use(cacheMiddleware(ServerCache))
	router.Use(LoggingMiddleware(_log))
	//router.Use(redirectToHTTPS()) // Redirect HTTP -> HTTPS

	// GIN ROUTER
	router.NoRoute(internal.NoFound)
	router.NoMethod(internal.NoMethod)
	router.GET("/", internal.Info)
	router.GET("/ping", internal.RespondPing)
	router.GET("/version", internal.Version)
	router.GET("/favicon.ico", internal.Favicon)
	router.GET("/get_countries", internal.GetCountries)
	router.POST("/get_team_members", internal.GetTeamMembers)
	router.POST("/get_player_card", internal.GetPlayerCard)
	router.POST("/login", internal.Login)

	tlsConfig := generateTLSConfig()

	if tlsConfig == nil {
		_log.Error("Error loading TLS certificates: %v", err)
		return
	}

	// SET INITIAL SERVER PARAMETERS
	server := &http.Server{
		Addr:           "0.0.0.0:" + strconv.Itoa(config.Server.Port),
		Handler:        router,
		ReadTimeout:    time.Duration(config.Server.ReadTimeoutSecond) * time.Second,
		WriteTimeout:   time.Duration(config.Server.WriteTimeoutSecond) * time.Second,
		MaxHeaderBytes: config.Server.MaxHeaderMB * 1024 * 1024,
		TLSConfig:      tlsConfig,
	}

	// GRACEFUL RESTART OR SHUTDOWN
	go catchSignal(server)

	// PERFORMANCE GOROUTINE CONFIGURATION
	maxCPUCore := runtime.NumCPU()
	maxGoroutines := maxCPUCore

	if config.Server.MaxGoRoutineParallel != 0 && config.Server.MaxGoRoutineParallel < maxCPUCore {
		maxGoroutines = config.Server.MaxGoRoutineParallel
	}
	_log.Info("Total Server CPU cores: %d | Total number of goroutines configured to run in parallel: %d", maxCPUCore, maxGoroutines)

	runtime.GOMAXPROCS(maxGoroutines)

	if config.Server.MaxGoRoutineParallel != maxCPUCore && config.Server.MaxGoRoutineParallel != 0 {
		_log.Warn("For best performance, the CPU cores and GoRoutine should have the same value.")
	}

	// START SERVER WITH CERTIFICATE
	err = server.ListenAndServeTLS(certificate, key)
	if err != nil {
		if !strings.Contains(err.Error(), "Server closed") {
			_log.Error(err)
			panic(err)
		} else {
			_log.Info(err)
		}
	}
}

func generateTLSConfig() *tls.Config {
	cert, err := tls.LoadX509KeyPair(certificate, key)
	if err != nil {
		_log.Error("Error loading TLS certificates: %v", err)
		return nil
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
}

func dbMiddleware(db *modules.DBInstance, log *logger.Log) gin.HandlerFunc {
	return func(c *gin.Context) {
		// save db connect in context
		c.Set("DataBaseInst", db)
		c.Set("DataBaseLog", log)
		c.Next()
	}
}

func cacheMiddleware(servCache *cache.Cache) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set("serverCache", servCache)
		c.Next()
	}
}

func LoggingMiddleware(log *logger.Log) gin.HandlerFunc {
	return func(c *gin.Context) {
		// save logger in context
		c.Set("customLogger", log)
		gin.DefaultWriter = log
		gin.DefaultErrorWriter = log

		start := time.Now()
		id := fmt.Sprintf("%06d", start.Nanosecond()/1e6)
		clientIP := c.ClientIP()
		method := c.Request.Method
		path := c.Request.URL.Path
		userAgent := c.Request.UserAgent()

		log.Info("Request | ClientIP: %s | ID: %v | Method: %s | Path: %s  | Start: %s | UserAgent: %s",
			clientIP, id, method, path, start, userAgent)
		if headerCheck {
			if hdrValue := c.Request.Header["App"]; len(hdrValue) == 0 || strings.ToLower(hdrValue[0]) != strings.ToLower(headerValue) {
				log.Warn("Source IP: %s | ID: %v | Message: You have received a request from an unknown source and it does not contain the key name in the header", clientIP, id)
				c.AbortWithStatus(http.StatusForbidden)
			}
		}

		// Process the request
		c.Next()

		// Log request details
		end := time.Now()
		latency := end.Sub(start)
		clientIP = c.ClientIP()
		method = c.Request.Method
		path = c.Request.URL.Path
		statusCode := c.Writer.Status()
		userAgent = c.Request.UserAgent()

		log.Info("Respond | ClientIP: %s | ID: %v | Method: %s | Path: %s | StatusCode: %d | Description: %s | Latency: %s | UserAgent: %s",
			clientIP, id, method, path, statusCode, internal.GetCodeMessage(statusCode), latency, userAgent)
	}
}

// GRACEFUL RESTART OR SHUTDOWN
func catchSignal(server *http.Server) {
	// Wait for interrupt signal to gracefully shut down the server with a timeout of 5 seconds
	quit := make(chan os.Signal)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	fmt.Println("[INFO] Shutdown Server ...")
	_log.Info("Shutdown Server ...")
	_log.Info(">> Good look for both of our sake")
	_log.Info(">> See you in the future")
	_log.Info("<< You mean the past")
	_log.Info(">> Exactly!")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)

	fmt.Println("[INFO] WithTimeout")
	defer cancel()
	if err := server.Shutdown(ctx); nil != err {
		fmt.Println("[ERROR] Server Shutdown problem:", err)
		_log.Error("Server Shutdown problem: %v", err)
	}
	/* A select statement is used to wait for the context to be canceled or expired. If the time limit of 5 seconds is
	reached, the instructions within this block are executed to report that a waiting time has occurred. */
	select {
	case <-ctx.Done():
		fmt.Println("[INFO] timeout of 5 seconds.")
		_log.Info("timeout of 5 seconds.")
	}

	fmt.Println("[INFO] Server exiting")
	_log.Info("Server exiting.")
}
