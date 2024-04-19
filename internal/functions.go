package internal

import (
	"GO_galletaApp_backend/modules"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/jpengineer/logger"
	"github.com/patrickmn/go-cache"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"os"
	"runtime"
	"time"
)

const (
	Continue            = 100
	SwitchingProtocols  = 101
	OK                  = 200
	Created             = 201
	Accepted            = 202
	NoContent           = 204
	MultipleChoices     = 300
	MovedPermanently    = 301
	Found               = 302
	NotModified         = 304
	BadRequest          = 400
	Unauthorized        = 401
	Forbidden           = 403
	NotFound            = 404
	MethodNotAllowed    = 405
	InternalServerError = 500
	NotImplemented      = 501
	BadGateway          = 502
	ServiceUnavailable  = 503
)

var httpCodeMessages = map[int]string{
	Continue:            "[Continue] Server received the requested and the client can continue sending the rest of the request.",
	SwitchingProtocols:  "[Switching Protocol] The server accept to change the requested protocol.",
	OK:                  "[OK] The request has been completed successfully.",
	Created:             "[Created] The request resulted in the creation of a new resource.",
	Accepted:            "[Accepted] The request has been accepted to processing, but hasn't been completed yet.",
	NoContent:           "[No Content] The request has been completed successfully, but there isn't body respond (e.g.: DELETE request)",
	MultipleChoices:     "[Multiple Choices] The request indicates multiple options available.",
	MovedPermanently:    "[Moved Permanently] The resource requested has been moved to other location permanently.",
	Found:               "[Found (or 303 See Other)] The resource requested is found temporarily in a different location.",
	NotModified:         "[Not Modified] Indicates that the resource hasn't been modified and can use the cache version.",
	BadRequest:          "[Bad Request] The client request is incorrect or it can't be understood.",
	Unauthorized:        "[Unauthorized] The client doesn't have the necessary authorization to access to the resource.",
	Forbidden:           "[Forbidden] The server understood the request but refuses to authorize it.",
	NotFound:            "[Not Found] The requested resource is not found in the server.",
	MethodNotAllowed:    "[Method Not Allowed] The requested HTTP method it doesn't allow for this route.",
	InternalServerError: "[Internal Server Error] Indicates an internal error in the server.",
	NotImplemented:      "[Not Implemented] The server can't achieve the request because it doesn't recognize the action.",
	BadGateway:          "[Bad Gateway] The server, as long as acted like a gateway or proxy, received an invalid respond from the upstream server.",
	ServiceUnavailable:  "[Service Unavailable] The server is not ready to handle the request. May be due to overload or maintenance.",
}

func GetCodeMessage(code int) string {
	message, exists := httpCodeMessages[code]
	if exists {
		return message
	}
	return "Code not found :( "
}

func GetCustomLogger(c *gin.Context) (*logger.Log, *logger.Log, error) {

	// Logger standard
	customLog, exists := c.Get("customLogger")
	if !exists {
		return nil, nil, errors.New("logger not found in context")
	}
	_log, ok := customLog.(*logger.Log)
	if !ok {
		return nil, nil, errors.New("logger type mismatch")
	}

	// Logger DB
	customDBLog, exists := c.Get("DataBaseLog")
	if !exists {
		return nil, nil, errors.New("logger DB not found in context")
	}
	_logDB, ok := customDBLog.(*logger.Log)
	if !ok {
		return nil, nil, errors.New("logger type mismatch")
	}
	return _log, _logDB, nil
}

func getDB(c *gin.Context) *modules.DBInstance {
	dbConn, ok := c.MustGet("DataBaseInst").(*modules.DBInstance)

	if !ok {
		c.IndentedJSON(http.StatusInternalServerError, gin.H{
			"message": GetCodeMessage(http.StatusInternalServerError),
			"error":   "DataBase type mismatch",
		})
		return nil
	}
	return dbConn
}

func getCache(c *gin.Context) *cache.Cache {
	serverCache, ok := c.MustGet("serverCache").(*cache.Cache)

	if !ok {
		c.IndentedJSON(http.StatusInternalServerError, gin.H{
			"error":   GetCodeMessage(http.StatusInternalServerError),
			"message": "serverCache type mismatch",
		})
		return nil
	}
	return serverCache
}

func NoFound(c *gin.Context) {
	c.IndentedJSON(http.StatusNotFound, gin.H{
		"message": GetCodeMessage(http.StatusNotFound),
	})
	return
}

func NoMethod(c *gin.Context) {
	c.IndentedJSON(http.StatusMethodNotAllowed, gin.H{
		"message": GetCodeMessage(http.StatusMethodNotAllowed),
	})
	return
}

func Info(c *gin.Context) {
	_log, _, err := GetCustomLogger(c)
	if err != nil {
		c.IndentedJSON(http.StatusInternalServerError, gin.H{
			"message": GetCodeMessage(http.StatusInternalServerError),
			"error":   err.Error(),
		})
		return
	}

	_log.Debug("function: Info()")
	c.File("./static/html/index.html")
	return
}

func RespondPing(c *gin.Context) {
	// TEST API
	_log, _, err := GetCustomLogger(c)
	if err != nil {
		c.IndentedJSON(http.StatusInternalServerError, gin.H{
			"message": GetCodeMessage(http.StatusInternalServerError),
			"error":   err.Error(),
		})
		return
	}

	_log.Debug("function: RespondPing()")
	c.IndentedJSON(http.StatusOK, gin.H{
		"message": GetCodeMessage(http.StatusOK),
		"data":    "pong",
	})
	return
}

func Version(c *gin.Context) {
	_log, _, err := GetCustomLogger(c)
	if err != nil {
		c.IndentedJSON(http.StatusInternalServerError, gin.H{
			"message": GetCodeMessage(http.StatusInternalServerError),
			"error":   err.Error(),
		})
		return
	}

	_log.Debug("function: Version()")

	tlsVersion := getTLSVersion(c.Request)
	certPEM, err := os.ReadFile("./certificates/certificate.pem")
	if err != nil {
		c.IndentedJSON(http.StatusInternalServerError, gin.H{
			"message": GetCodeMessage(http.StatusInternalServerError),
			"error":   err.Error(),
		})
		_log.Error(err.Error())
		return
	}
	// decode PEM block
	block, _ := pem.Decode(certPEM)
	if block == nil {
		c.IndentedJSON(http.StatusInternalServerError, gin.H{
			"message": GetCodeMessage(http.StatusInternalServerError),
			"data":    "Couldn't decode PEM certificate",
		})
		_log.Error("Couldn't decode PEM certificate")
		return
	}
	// certificate parse
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		c.IndentedJSON(http.StatusInternalServerError, gin.H{
			"message": GetCodeMessage(http.StatusInternalServerError),
			"data":    err.Error(),
		})
		_log.Error(err.Error())
		return
	}

	_log.Debug("[Certificate] Subject: %s | Issuer: %s | Serial Number: %s | Not Before: %s | Not After: %s",
		cert.Subject, cert.Issuer.Organization, cert.SerialNumber, cert.NotBefore, cert.NotAfter)

	_log.Debug("[Server] Golang: %s | Gin: %s | TLS: %s", runtime.Version(), gin.Version, tlsVersion)

	data := make(map[string]interface{})
	data["Golang"] = runtime.Version()
	data["Gin"] = gin.Version
	data["TLS"] = tlsVersion
	data["Cert Issuer"] = cert.Issuer.Organization[0]
	data["Cert Date of issue"] = cert.NotBefore
	data["Cert Expiration Day"] = cert.NotAfter

	c.IndentedJSON(http.StatusOK, gin.H{
		"message": GetCodeMessage(http.StatusOK),
		"data":    data,
	})
	return
}

func getTLSVersion(req *http.Request) string {
	if req.TLS != nil {
		switch req.TLS.Version {
		case tls.VersionTLS10:
			return "TLS 1.0"
		case tls.VersionTLS11:
			return "TLS 1.1"
		case tls.VersionTLS12:
			return "TLS 1.2"
		case tls.VersionTLS13:
			return "TLS 1.3"
		default:
			return "Unknown"
		}
	}
	return "Don't use TLS"
}

func Favicon(c *gin.Context) {
	c.File("./static/favicon.ico")
}

// ======================================= GET METHODS =======================================

func GetCountries(c *gin.Context) {
	_log, _logDB, err := GetCustomLogger(c)
	if err != nil {
		c.IndentedJSON(http.StatusInternalServerError, gin.H{
			"message": GetCodeMessage(http.StatusInternalServerError),
			"error":   err.Error(),
		})
		return
	}

	_log.Debug("GetCountries()")
	dbInstance := getDB(c)

	var countries []Country
	err = dbInstance.Select(Query["get_countries"], &countries)
	if err != nil {
		_logDB.Error("An error has occurred in the database. Try again later: %s", err)
		c.IndentedJSON(http.StatusInternalServerError, gin.H{
			"message": GetCodeMessage(http.StatusInternalServerError),
			"error":   "An error has occurred in the database. Try again later.",
		})
		return
	}

	_logDB.Debug("countries: %s", countries)
	c.IndentedJSON(http.StatusOK, gin.H{
		"message": GetCodeMessage(http.StatusOK),
		"data":    countries,
	})
	return
}

// =======================================  POST METHODS =======================================

func GetTeamMembers(c *gin.Context) {
	type PlayerIdPayload struct {
		TeamId string `json:"teamId"`
	}

	var payload PlayerIdPayload

	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": GetCodeMessage(http.StatusBadRequest),
			"error":   err.Error(),
		})
		return
	}

	_log, _logDB, err := GetCustomLogger(c)
	if err != nil {
		c.IndentedJSON(http.StatusInternalServerError, gin.H{
			"message": GetCodeMessage(http.StatusInternalServerError),
			"error":   err.Error(),
		})
		return
	}
	_log.Debug("GetTeamMembers()")
	dbInstance := getDB(c)

	var members []TeamMembers

	_logDB.Debug("query: %v | args: %v", Query["get_team_members"], payload.TeamId)
	err = dbInstance.Select(Query["get_team_members"], &members, payload.TeamId)
	if err != nil {
		_logDB.Error("An error has occurred in the database. Try again later: %s", err)

		c.IndentedJSON(http.StatusInternalServerError, gin.H{
			"message": GetCodeMessage(http.StatusInternalServerError),
			"error":   "An error has occurred in the database. Try again later.",
		})
		return
	}

	if members == nil || len(members) == 0 {
		_log.Error("ClientIP: %s | Team: %s (Not Found)",
			c.ClientIP(), payload.TeamId)
		c.IndentedJSON(http.StatusUnauthorized, gin.H{
			"message": GetCodeMessage(http.StatusUnauthorized),
			"error":   "Team not found",
		})
		return
	}

	jsonFinalObject, err := json.Marshal(members)
	if err != nil {
		_log.Error("An error has occurred in the server when trying to build the final Team Members object. Try again later: %s", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": GetCodeMessage(http.StatusInternalServerError),
			"error":   "An error has occurred in the server when trying to build the final Team Members object. Try again later.",
		})
		return
	}

	_log.Debug("Final Object: %v", members)
	c.IndentedJSON(http.StatusOK, gin.H{
		"message": GetCodeMessage(http.StatusOK),
		"data":    string(jsonFinalObject),
	})
	return

}

func GetPlayerCard(c *gin.Context) {
	type PlayerIdPayload struct {
		PlayerId string `json:"teamId"`
	}

	var payload PlayerIdPayload

	if err := c.BindJSON(&payload); err != nil {

		c.JSON(http.StatusBadRequest, gin.H{
			"message": GetCodeMessage(http.StatusBadRequest),
			"error":   err.Error(),
		})
		return
	}

	fmt.Println(payload.PlayerId)

	//_cache := getCache(c)
	_log, _logDB, err := GetCustomLogger(c)
	if err != nil {
		c.IndentedJSON(http.StatusInternalServerError, gin.H{
			"message": GetCodeMessage(http.StatusInternalServerError),
			"error":   err.Error(),
		})
		return
	}
	_log.Debug("GetPlayerCard()")
	dbInstance := getDB(c)

	var playerCard []PlayerCard

	_logDB.Debug("query: %v | args: %v", Query["get_player_card"], payload.PlayerId)
	err = dbInstance.Select(Query["get_player_card"], &playerCard, payload.PlayerId)
	if err != nil {
		_logDB.Error("An error has occurred in the database. Try again later: %s", err)

		c.IndentedJSON(http.StatusInternalServerError, gin.H{
			"message": GetCodeMessage(http.StatusInternalServerError),
			"error":   "An error has occurred in the database. Try again later.",
		})
		return
	}

	if playerCard == nil || len(playerCard) == 0 {
		_log.Error("ClientIP: %s | Team: %s (Not Found)",
			c.ClientIP(), payload.PlayerId)
		c.IndentedJSON(http.StatusUnauthorized, gin.H{
			"message": GetCodeMessage(http.StatusUnauthorized),
			"error":   "Player not found",
		})
		return
	}

	jsonFinalObject, err := json.Marshal(playerCard[0])
	if err != nil {
		_log.Error("An error has occurred in the server when trying to build the final Team Members object. Try again later: %s", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": GetCodeMessage(http.StatusInternalServerError),
			"error":   "An error has occurred in the server when trying to build the final Team Members object. Try again later.",
		})
		return
	}

	_log.Debug("Final Object: %v", playerCard[0])
	c.IndentedJSON(http.StatusOK, gin.H{
		"message": GetCodeMessage(http.StatusOK),
		"data":    string(jsonFinalObject),
	})
	return
}

func Login(c *gin.Context) {
	loginUser := LoginUser{}

	if err := c.BindJSON(&loginUser); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": GetCodeMessage(http.StatusBadRequest),
			"error":   err.Error(),
		})
		return
	}

	_cache := getCache(c)
	_log, _logDB, err := GetCustomLogger(c)
	if err != nil {
		c.IndentedJSON(http.StatusInternalServerError, gin.H{
			"message": GetCodeMessage(http.StatusInternalServerError),
			"error":   err.Error(),
		})
		return
	}
	_log.Debug("Login()")
	dbInstance := getDB(c)

	finalObject := make(map[string]interface{})
	var user []Player
	var teams []Team
	var members []TeamMembers
	var playerConfig []PlayerConfiguration
	var systemConfig []SystemConfiguration

	var attempts = 0

	_logDB.Debug("query: %v | args: %v", Query["login"], loginUser.Name)
	err = dbInstance.Select(Query["login"], &user, loginUser.Name)
	if err != nil {
		_logDB.Error("An error has occurred in the database. Try again later: %s", err)

		c.IndentedJSON(http.StatusInternalServerError, gin.H{
			"message": GetCodeMessage(http.StatusInternalServerError),
			"error":   "An error has occurred in the database. Try again later.",
		})
		return
	}

	if user == nil || len(user) == 0 {
		// verify cache
		if attempt, found := _cache.Get(c.ClientIP()); found {
			attempts = attempt.(int)
			attempts++
			_cache.Set(c.ClientIP(), attempts, cache.DefaultExpiration)
		} else {
			attempts = 1
			_cache.Set(c.ClientIP(), attempts, cache.DefaultExpiration)
		}
		_log.Error("ClientIP: %s | User: %s (Not Found)| Login: Failed | Attempts: %d | Sleep: 5s | Cache Items: %d",
			c.ClientIP(), loginUser.Name, attempts, _cache.ItemCount())
		time.Sleep(5 * time.Second)

		c.IndentedJSON(http.StatusUnauthorized, gin.H{
			"message": GetCodeMessage(http.StatusUnauthorized),
			"error":   "Login failed",
		})
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(user[0].Password), []byte(loginUser.Password))

	if err != nil {
		// verify cache
		if attempt, found := _cache.Get(c.ClientIP()); found {
			attempts = attempt.(int)
			attempts++
			_cache.Set(c.ClientIP(), attempts, cache.DefaultExpiration)
		} else {
			attempts = 1
			_cache.Set(c.ClientIP(), attempts, cache.DefaultExpiration)
		}
		_log.Error("ClientIP: %s | User: %s | Login: Failed | Attempts: %d | Sleep: 5s | Cache Items: %d",
			c.ClientIP(), loginUser.Name, attempts, _cache.ItemCount())
		time.Sleep(5 * time.Second)

		c.IndentedJSON(http.StatusUnauthorized, gin.H{
			"message": GetCodeMessage(http.StatusUnauthorized),
			"error":   "Login failed",
		})
		return
	}

	if attempt, found := _cache.Get(c.ClientIP()); found {
		attempts = attempt.(int)
		attempts++
		_cache.Delete(c.ClientIP())
	} else {
		attempts = 1
	}

	_log.Info("ClientIP: %s | User: %s | Login: Success | Attempts: %v | Sleep: 0s | Cache Items: %d",
		c.ClientIP(), loginUser.Name, attempts, _cache.ItemCount())

	finalObject["user"] = user[0]

	// GET TEAMS
	_logDB.Debug("query: %v | args: %v", Query["get_team"], user[0].Id)
	err = dbInstance.Select(Query["get_team"], &teams, user[0].Id)
	if err != nil {
		_logDB.Error("An error has occurred in the database. Try again later: %s", err)
	}
	finalObject["teams"] = teams

	// GET MAIN TEAMS MEMBERS
	var mainTeamId string

	for _, team := range teams {
		if team.IsMainTeam {
			mainTeamId = team.Id
			break
		}
	}
	fmt.Println("TeamID:", mainTeamId)
	if len(mainTeamId) != 0 {
		_logDB.Debug("query: %v | args: %v, %v", Query["get_team_members"], mainTeamId, user[0].Id)
		err = dbInstance.Select(Query["get_team_members"], &members, mainTeamId, user[0].Id)
		if err != nil {
			_logDB.Error("An error has occurred in the database. Try again later: %s", err)
		}
		finalObject["teamMembers"] = members
	}

	// GET PLAYER CONFIGURATION
	_logDB.Debug("query: %v | args: %v", Query["get_profile_configurations"], user[0].Id)
	err = dbInstance.Select(Query["get_profile_configurations"], &playerConfig, user[0].Id)
	if err != nil {
		_logDB.Error("An error has occurred in the database. Try again later: %s", err)
		finalObject["playerConfig"] = playerConfig
	} else {
		finalObject["playerConfig"] = playerConfig[0]
	}

	// GET SYSTEM CONFIGURATION
	_logDB.Debug("query: %v | args: %v", Query["get_system_configurations"], user[0].Id)
	err = dbInstance.Select(Query["get_system_configurations"], &systemConfig, user[0].Id)
	if err != nil {
		_logDB.Error("An error has occurred in the database. Try again later: %s", err)
		finalObject["systemConfig"] = systemConfig
	} else {
		finalObject["systemConfig"] = systemConfig[0]
	}

	jsonFinalObject, err := json.Marshal(finalObject)
	if err != nil {
		_log.Error("An error has occurred in the server when trying to build the final user object. Try again later: %s", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": GetCodeMessage(http.StatusInternalServerError),
			"error":   "An error has occurred in the server when trying to build the final user object. Try again later.",
		})
		return
	}

	_log.Debug("Final Object: %v", finalObject)
	c.IndentedJSON(http.StatusOK, gin.H{
		"message": GetCodeMessage(http.StatusOK),
		"data":    string(jsonFinalObject),
	})
	return
}
