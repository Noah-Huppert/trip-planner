package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Noah-Huppert/goconf"
	"github.com/Noah-Huppert/gointerrupt"
	"github.com/Noah-Huppert/golog"
	"github.com/dwin/goArgonPass"
	"github.com/gorilla/mux"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
	"gopkg.in/go-playground/validator.v9"
)

// GORMLogger adapts the servers logger for use in GORM
type GORMLogger struct {
	log golog.Logger
}

// Print implements the gorm logger interface
func (l GORMLogger) Print(vals ...interface{}) {
	strs := []string{}
	for _, val := range vals {
		strs = append(strs, fmt.Sprintf("%#v", val))
	}

	l.log.Infof("gorm log: %s", strings.Join(strs, ", "))
}

// Config configures the app
type Config struct {
	// HTTPAddr is the address for the HTTP server
	HTTPAddr string `validate:"required" default:":5000"`

	// DBConnOpts are database connection options
	DBConnOpts string `validate:"required" default:"host=localhost user=dev-trip-planner password=dev-trip-planner dbname=dev-trip-planner sslmode=disable"`
}

// User represents a person who uses trip planner
type User struct {
	gorm.Model

	// Name of user
	Name string `gorm:"NOT NULL" json:"name"`

	// PasswordHash is the argon hash of the plaintext password
	PasswordHash string `gorm:"NOT NULL" json:"-"`
}

// InviteCode provides permission to create a user
type InviteCode struct {
	gorm.Model

	// Code is the invite code
	Code string `gorm:"NOT NULL;UNIQUE"`
}

// BaseHandler holds some useful fields which every handler might use
type BaseHandler struct {
	log golog.Logger
	db  *gorm.DB
}

// GetChild creates a derrivite BaseHandler with a logger setup to indicate
// which handler is using it
func (h BaseHandler) GetChild(logName string) BaseHandler {
	base := BaseHandler{
		log: h.log.GetChild(logName),
		db:  h.db,
	}

	base.db.SetLogger(GORMLogger{
		log: base.log,
	})

	return base
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

// WriteJSON writes JSON
func (h BaseHandler) WriteJSON(writer io.Writer, value interface{}) {
	encode := json.NewEncoder(writer)
	if err := encode.Encode(value); err != nil {
		h.log.Errorf("failed to write JSON value=%#v, error: %s", value, err)
	}
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

	// InviteCode is a secret provided to the user which allows them to create
	// a user.
	InviteCode string `json:"invite_code" validate:"required"`
}

// CreateUserResp is the response to the create user endpoint containing the
// new user.
type CreateUserResp struct {
	User User `json:"user"`
}

// ServeHTTP creates a user
func (h CreateUserHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Decode body
	var createReq CreateUserReq
	if err := DecodeAndValidate(r.Body, &createReq); err != nil {
		h.WriteErr(w, fmt.Errorf("failed to read body: %s", err), nil)
		return
	}

	// Check invite code
	inviteCode := InviteCode{Code: createReq.InviteCode}

	err := h.db.Where(&inviteCode).Find(&InviteCode{}).Error
	if gorm.IsRecordNotFoundError(err) {
		h.WriteErr(w, fmt.Errorf("invalid invite code"), nil)
		return
	} else if err != nil {
		h.WriteErr(w, fmt.Errorf("failed to check invite code"),
			fmt.Errorf("failed to query DB: %#v", err))
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
	if err := h.db.Create(&user).Error; err != nil {
		h.WriteErr(w, fmt.Errorf("failed to save user in database"), err)
		return
	}

	// Delete invite code
	if err := h.db.Delete(&inviteCode).Error; err != nil {
		h.WriteErr(w, nil,
			fmt.Errorf("failed to delete invite code: %s", err))
		return
	}

	// Respond with new user
	h.WriteJSON(w, user)
}

// InviteCodeExpirer deletes invite codes which are older than a day
type InviteCodeExpirer struct {
	log     golog.Logger
	db      *gorm.DB
	ctxPair gointerrupt.CtxPair
}

func (e InviteCodeExpirer) goroutine() {
	ticker := time.NewTicker(1 * time.Minute)

	for {
		select {
		case <-e.ctxPair.Graceful().Done():
			return
			break
		case <-ticker.C:
			rows, err := e.db.Where("age(created_at) >= interval '1 day'").
				Find(&InviteCode{}).Rows()
			if err == sql.ErrNoRows {
				continue
			} else if err != nil {
				e.log.Errorf("failed to get expired invite codes: %s", err)
				continue
			}

			for rows.Next() {
				var inviteCode InviteCode
				if err := rows.Scan(&inviteCode); err != nil {
					e.log.Errorf("failed to scan invite code into "+
						"struct: %s", err)
					continue
				}

				err := e.db.Delete(&inviteCode).Error
				if err != nil {
					e.log.Errorf("failed to delete old invite code: %s",
						err)
					continue
				}

				e.log.Infof("deleted invite code id=%d", inviteCode.ID)
			}

			if err := rows.Err(); err != nil {
				e.log.Errorf("failed to iterate over expired invite "+
					"codes: %s", err)
				continue
			}
			break
		}
	}
}

func main() {
	ctxPair := gointerrupt.NewCtxPair(context.Background())
	log := golog.NewLogger("api")
	var wg sync.WaitGroup

	// Load config
	cfgLdr := goconf.NewLoader()
	cfgLdr.AddConfigPath("/etc/trip-planner/*")
	cfgLdr.AddConfigPath("./*")

	var cfg Config
	if err := cfgLdr.Load(&cfg); err != nil {
		log.Fatalf("failed to load configuration: %s", err)
	}

	// Connect to DB
	db, err := gorm.Open("postgres", cfg.DBConnOpts)
	if err != nil {
		log.Fatalf("failed to connect to DB: %s", err)
	}

	db.SetLogger(GORMLogger{
		log: log,
	})

	// Determine what action to run, based on received command line arguments
	adminCmd := ""
	if len(os.Args) > 1 {
		adminCmd = os.Args[1]
	}

	switch adminCmd {
	case "db-migrate":
		// Migrate DB
		tableDefs := map[string]interface{}{
			"users":        &User{},
			"invite_codes": &InviteCode{},
		}

		for tableName, def := range tableDefs {
			if err := db.AutoMigrate(def).Error; err != nil {
				log.Fatalf("failed to migrate %s table: %s", tableName, err)
			}
			log.Debugf("migrated %s table", tableName)
		}
		break
	case "create-invite-code":
		// Create an invite code
		code := [64]byte{}
		if _, err := rand.Read(code[:]); err != nil {
			log.Fatalf("failed to generate random invite code: %s", err)
		}

		// Base64 encode
		b64Code := base64.StdEncoding.EncodeToString(code[:])

		// Save in database
		inviteCode := InviteCode{
			Code: b64Code,
		}

		if err := db.Create(&inviteCode).Error; err != nil {
			log.Fatalf("failed to save invite code in DB: %s", err)
		}

		// Print invite code
		log.Infof("invite code: %s", b64Code)
		break
	default:
		// Start goroutine to expire old invite codes
		inviteCodeExpirer := InviteCodeExpirer{
			db:      db,
			log:     log.GetChild("invite code expirer"),
			ctxPair: ctxPair,
		}

		go inviteCodeExpirer.goroutine()

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
}
