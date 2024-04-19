package modules

import (
	"github.com/jpengineer/logger"
	"strings"
)

func InitLogDB(name string, path string, level string, maxSizeMb int, maxBackup int) *logger.Log {
	LogDB, _ := logger.Start(name+"_DB.log", path, strings.ToUpper(level))
	LogDB.TimestampFormat(logger.TS.Special)
	LogDB.Rotation(maxSizeMb, maxBackup)
	return LogDB
}

func InitLog(name string, path string, level string, maxSizeMb int, maxBackup int) *logger.Log {
	Log, _ := logger.Start(name+"_server.log", path, strings.ToUpper(level))
	Log.TimestampFormat(logger.TS.Special)
	Log.Rotation(maxSizeMb, maxBackup)
	return Log
}
