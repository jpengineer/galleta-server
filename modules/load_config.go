package modules

import (
	"errors"
	"fmt"
	"github.com/go-ini/ini"
)

type Config struct {
	Database struct {
		Username string
		Password string
		Database string
		Schema   string
		Host     string
		Port     int
	}
	Server struct {
		Dev                  bool
		Name                 string
		Port                 int
		ReadTimeoutSecond    int
		WriteTimeoutSecond   int
		MaxHeaderMB          int
		MaxGoRoutineParallel int
		AutoJWT              bool
		HeaderKey            bool
		HeaderValue          string
	}
	Cache struct {
		ExpirationTime  int
		CleanUpInterval int
	}
	Log struct {
		Level     string
		Path      string
		MaxSizeMb int
		MaxBackup int
	}
}

func LoadConfig() (Config, error) {
	var conf Config

	cfg, err := ini.Load("./config/galleta_app.conf")
	if err != nil {
		return Config{}, errors.New(fmt.Sprintf("Error loading configuration: %v\n", err))
	}

	dbSection := cfg.Section("database")
	conf.Database.Host = dbSection.Key("host").String()
	conf.Database.Port, _ = dbSection.Key("port").Int()
	conf.Database.Database = dbSection.Key("database").String()
	conf.Database.Schema = dbSection.Key("schema").String()
	conf.Database.Username = dbSection.Key("username").String()
	conf.Database.Password = dbSection.Key("password").String()

	serverSection := cfg.Section("server")
	conf.Server.Dev, _ = serverSection.Key("dev").Bool()
	conf.Server.Name = serverSection.Key("name").String()
	conf.Server.Port, _ = serverSection.Key("port").Int()
	conf.Server.ReadTimeoutSecond, _ = serverSection.Key("readTimeoutSecond").Int()
	conf.Server.WriteTimeoutSecond, _ = serverSection.Key("writeTimeoutSecond").Int()
	conf.Server.MaxHeaderMB, _ = serverSection.Key("maxHeaderMB").Int()
	conf.Server.MaxGoRoutineParallel, _ = serverSection.Key("maxGoRoutineParallel").Int()
	conf.Server.AutoJWT, _ = serverSection.Key("autoJWT").Bool()
	conf.Server.HeaderKey, _ = serverSection.Key("headerKey").Bool()
	conf.Server.HeaderValue = serverSection.Key("headerValue").String()

	cacheSection := cfg.Section("cache")
	conf.Cache.ExpirationTime, _ = cacheSection.Key("expirationTime").Int()
	conf.Cache.CleanUpInterval, _ = cacheSection.Key("cleanUpInterval").Int()

	logSection := cfg.Section("log")
	conf.Log.Level = logSection.Key("level").String()
	conf.Log.Path = logSection.Key("path").String()
	conf.Log.MaxSizeMb, _ = logSection.Key("maxSizeMB").Int()
	conf.Log.MaxBackup, _ = logSection.Key("maxBackup").Int()

	return conf, nil
}
