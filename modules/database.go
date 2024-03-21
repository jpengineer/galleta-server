package modules

import (
	"context"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jpengineer/logger"
	"os"
	"reflect"
)

type DBInstance struct {
	db *pgxpool.Pool
}

func (dbi *DBInstance) InitDB(conf *Config, logDB *logger.Log) error {
	var err error
	logDB.Info("DB user: %s | DB name: %s | DB schema: %s | DB host: %s | DB port: %d",
		conf.Database.Username, conf.Database.Database, conf.Database.Schema, conf.Database.Host, conf.Database.Port)

	dbData := conf.Database
	dbString := fmt.Sprintf("user=%s password=%s host=%s port=%d dbname=%s sslmode=disable search_path=%s",
		dbData.Username, dbData.Password, dbData.Host, dbData.Port, dbData.Database, dbData.Schema)

	logDB.Debug("Postgres connection string: %s", dbString)

	// Create pool
	dbi.db, err = pgxpool.New(context.Background(), dbString)

	if err != nil {
		_, err = fmt.Fprintf(os.Stderr, "Unable to connect to database: %v\n", err)
		logDB.Error(err)
		return err
	}

	err = dbi.db.Ping(context.Background())
	if err != nil {
		logDB.Error("The Database it doesn't available: ", err)
		return err
	}

	var version string
	sqlStatement := "Select version()"
	err = dbi.db.QueryRow(context.Background(), sqlStatement).Scan(&version)
	if err != nil {
		logDB.Error("An error occurred while trying to get the version from the database: %v", err)
		return err
	}

	logDB.Info("Open Connection Database")
	logDB.Info(version)
	return nil
}

// Insert TODO No implemented
//func (dbi *DBInstance) Insert(title, status string) error {
//	_, err := dbi.db.Exec("INSERT INTO todos (title, status) VALUES ($1, $2)", title, status)
//	return err
//}

// Delete TODO No implemented
/*func (dbi *DBInstance) Delete(id int) error {
	_, err := dbi.db.Exec("DELETE FROM todos WHERE id = $1", id)
	return err
}*/

// Select Investigate how can I Implemented
func (dbi *DBInstance) Select(query string, result interface{}, args ...interface{}) error {
	// Execute SQL query with optional arguments ($n)
	rows, err := dbi.db.Query(context.Background(), query, args...)
	if err != nil {
		return err
	}
	defer rows.Close()

	// Check if 'result' is a pointer to struct or structs slice
	v := reflect.ValueOf(result)
	if v.Kind() != reflect.Ptr || v.Elem().Kind() != reflect.Slice {
		return errors.New("'result' must be a pointer to a struct slice")
	}

	// Obtain type of element of the slice. Equivalent to reflect.TypeOf(Country{})
	elemType := v.Elem().Type().Elem()

	// Create an empty map for mapping column or field names in the structure
	colMap := make(map[string]int)
	for i := 0; i < elemType.NumField(); i++ {
		colName := elemType.Field(i).Tag.Get("db") // Column name in the database
		colMap[colName] = i
	}

	for rows.Next() {
		// Create a  new vale of struct. Is the same item := country{}
		item := reflect.New(elemType).Elem()

		// Create an interface for each column in the row
		values := make([]interface{}, len(colMap))
		for _, colIndex := range colMap {
			values[colIndex] = item.Field(colIndex).Addr().Interface()
		}

		if err := rows.Scan(values...); err != nil {
			return err
		}

		// Add the struct to result (slice of structures). V is a pointer to struct.
		v.Elem().Set(reflect.Append(v.Elem(), item))
	}

	return nil
}

func (dbi *DBInstance) Close() {
	if dbi.db != nil {
		dbi.db.Close()
	}
}

func NewDBInstance() *DBInstance {
	return &DBInstance{}
}
