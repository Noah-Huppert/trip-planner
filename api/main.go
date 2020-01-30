package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"

	"github.com/Noah-Huppert/goconf"
	"github.com/Noah-Huppert/gointerrupt"
	"github.com/Noah-Huppert/golog"
	"github.com/dwin/goArgonPass"
	"github.com/gorilla/mux"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
	"gopkg.in/go-playground/validator.v9"
)

// Config configures the app
type Config struct {
	// HTTPAddr is the address for the HTTP server
	HTTPAddr string `validate:"required" default:":5000"`

	// DBConnOpts are database connection options
	DBConnOpts string `validate:"required" default:"host=localhost user=dev-trip-planner password=dev-trip-planner dbname=dev-trip-planner"`
}

// User represents a person who uses trip planner
type User struct {
	gorm.Model

	// Name of user
	Name string `gorm:"NOT NULL"`

	// PasswordHash is the
	PasswordHash string `gorm:"NOT NULL"`
}

// BaseHandler holds some useful fields which every handler might use
type BaseHandler struct {
	log golog.Logger
	db  *gorm.DB
}

// GetChild creates a derrivite BaseHandler with a logger setup to indicate
// which handler is using it
func (h BaseHandler) GetChild(logName string) BaseHandler {
	return BaseHandler{
		log: h.log.GetChild(logName),
		db:  h.db,
	}
}

// WriteErr writes and logs an error response as JSON
func (h BaseHandler) WriteErr(w io.Writer, pubErr, privErr error) {
	if pubErr == nil {
		pubErr = fmt.Errorf("unknown server error")
	}

	h.log.Errorf("public error=%s, private error=%s", pubErr, privErr)
	if _, err := fmt.Fprintf(w, "{\"error\": \"%s\"}", pubErr); err != nil {
		h.log.Errorf("failed to write error response: %s", err)
	}
}

// DecodeAndValidate decodes bytes as JSON and validates the resulting struct
func DecodeAndValidate(reader io.Reader, value interface{}) error {
	// Decode
	decoder := json.NewDecoder(reader)
	if err := decoder.Decode(value); err != nil {
		return fmt.Errorf("failed to decode JSON: %s", err)
	}

	// Validate
	validate := validator.New()
	if err := validate.Struct(value); err != nil {
		return fmt.Errorf("not valid: %s", err)
	}

	return nil
}

// CreateUserHandler creates a user
type CreateUserHandler struct {
	BaseHandler
}

// CreateUserReq are the fields required by CreateUserHandler. Most fields
// duplicate User struct fields.
type CreateUserReq struct {
	Name     string `json:"name" validate:"required"`
	Password string `json:"password" validate:"required"`
}

// ServeHTTP creates a user
func (h CreateUserHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Decode body
	var createReq CreateUserReq
	if err := DecodeAndValidate(r.Body, &createReq); err != nil {
		h.WriteErr(w, fmt.Errorf("failed to read body: %s", err), nil)
		return
	}

	// Hash user password
	hashedPw, err := argonpass.Hash(createReq.Password)
	if err != nil {
		h.WriteErr(w, nil, fmt.Errorf("failed to hash password: %s", err))
		return
	}

	user := User{
		Name:         createReq.Name,
		PasswordHash: hashedPw,
	}

	// Save in DB
	if err := h.db.Create(user).Error; err != nil {
		h.WriteErr(w, fmt.Errorf("failed to save user in database"), err)
		return
	}
}

func main() {
	ctxPair := gointerrupt.NewCtxPair(context.Background())
	log := golog.NewLogger("api")
	var wg sync.WaitGroup

	// Load config
	var cfg Config
	cfgLdr := goconf.NewLoader()
	cfgLdr.AddConfigPath("/etc/trip-planner/*")
	cfgLdr.AddConfigPath("./*")
	if err := cfgLdr.Load(&cfg); err != nil {
		log.Fatalf("failed to load configuration: %s", err)
	}

	// Connect to DB
	db, err := gorm.Open("postgres", cfg.DBConnOpts)
	if err != nil {
		log.Fatalf("failed to connect to DB: %s", err)
	}

	// Start HTTP API
	baseHdlr := BaseHandler{
		log: log,
		db:  db,
	}

	router := mux.NewRouter()
	router.Handle("/api/v0/users", CreateUserHandler{
		BaseHandler: baseHdlr.GetChild("create user"),
	}).Methods("POST")

	server := http.Server{
		Addr:    cfg.HTTPAddr,
		Handler: router,
	}

	wg.Add(1)
	go func() {
		log.Debugf("starting HTTP server on \"%s\"", cfg.HTTPAddr)

		err := server.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			log.Fatalf("failed to run HTTP server: %s", err)
		}
		wg.Done()
	}()

	go func() {
		<-ctxPair.Graceful().Done()
		if err := server.Close(); err != nil {
			log.Fatalf("failed to close HTTP server: %s", err)
		}
	}()

	// Wait until server is done
	doneChan := make(chan int, 1)
	go func() {
		wg.Wait()
		doneChan <- 1
	}()

	go func() {
		<-ctxPair.Harsh().Done()
		doneChan <- 1
	}()

	<-doneChan
}
