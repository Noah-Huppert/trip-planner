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
	"github.com/dgrijalva/jwt-go"
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

	// JWTSecret is the secret used to sign JWT API authentication tokens
	JWTSecret []byte `validate:"required" default:"dev-trip-planner-secret"`
}

// User represents a person who uses trip planner
type User struct {
	gorm.Model

	// Email of user
	Email string `gorm:"NOT NULL;UNIQUE" json:"email"`

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

// InviteCodeExpirer deletes invite codes which are older than a day
type InviteCodeExpirer struct {
	log     golog.Logger
	db      *gorm.DB
	ctxPair gointerrupt.CtxPair
}

// goroutine checks every minute for expired invite codes and deletes them
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

// BaseHandler holds some useful fields which every handler might use
type BaseHandler struct {
	log golog.Logger
	db  *gorm.DB
	cfg Config
}

// GetChild creates a derrivite BaseHandler with a logger setup to indicate
// which handler is using it
func (h BaseHandler) GetChild(logName string) BaseHandler {
	base := BaseHandler{
		log: h.log.GetChild(logName),
		db:  h.db,
		cfg: h.cfg,
	}

	base.db.SetLogger(GORMLogger{
		log: base.log,
	})

	return base
}

// WriteErr writes and logs an error response as JSON.
// If pubErr is nil then an error saying "unknown server error" is sent.
// If code is -1 then http.StatusInternalServerError is used.
func (h BaseHandler) WriteErr(w http.ResponseWriter, code int, pubErr,
	privErr error) {

	// Write status code
	if code == -1 {
		code = http.StatusInternalServerError
	}
	w.WriteHeader(code)

	// Write Content-Type header
	w.Header().Set("Content-Type", "application/json")

	// Set default public error
	if pubErr == nil {
		pubErr = fmt.Errorf("unknown server error")
	}

	// Log error
	h.log.Errorf("public error=%s, private error=%s", pubErr, privErr)

	// Write JSON response
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

// WriteJSON writes JSON.
// If status is -1 then http.StatusOK is used.
func (h BaseHandler) WriteJSON(writer http.ResponseWriter, status int,
	value interface{}) {

	// Set default status
	if status == -1 {
		status = http.StatusOK
	}

	// Write JSON
	writer.Header().Set("Content-Type", "application/json")

	encode := json.NewEncoder(writer)
	if err := encode.Encode(value); err != nil {
		h.log.Errorf("failed to write JSON value=%#v, error: %s", value, err)
	}
}

// AuthTokenCookie is the name of the authentication token cookie key.
const AuthTokenCookie string = "Authentication-Token"

// CreateUserHandler creates a user
type CreateUserHandler struct {
	BaseHandler
}

// CreateUserReq are the fields required by CreateUserHandler. Most fields
// duplicate User struct fields.
type CreateUserReq struct {
	Email    string `json:"email" validate:"required,email"`
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
		h.WriteErr(w, -1, fmt.Errorf("failed to read body: %s", err), nil)
		return
	}

	// Check invite code
	inviteCode := InviteCode{Code: createReq.InviteCode}

	err := h.db.Where(&inviteCode).Find(&InviteCode{}).Error
	if gorm.IsRecordNotFoundError(err) {
		h.WriteErr(w, http.StatusNotFound,
			fmt.Errorf("invalid invite code"), nil)
		return
	} else if err != nil {
		h.WriteErr(w, -1, fmt.Errorf("failed to check invite code"),
			fmt.Errorf("failed to query DB: %#v", err))
		return
	}

	// Hash user password
	hashedPw, err := argonpass.Hash(createReq.Password)
	if err != nil {
		h.WriteErr(w, -1, nil, fmt.Errorf("failed to hash password: %s", err))
		return
	}

	user := User{
		Email:        createReq.Email,
		Name:         createReq.Name,
		PasswordHash: hashedPw,
	}

	// Save in DB
	if err := h.db.Create(&user).Error; err != nil {
		h.WriteErr(w, -1, fmt.Errorf("failed to save user in database"), err)
		return
	}

	// Delete invite code
	if err := h.db.Delete(&inviteCode).Error; err != nil {
		h.WriteErr(w, -1, nil,
			fmt.Errorf("failed to delete invite code: %s", err))
		return
	}

	// Respond with new user
	h.WriteJSON(w, -1, user)
}

// AuthUserHandler authenticate a user's password is correct and distribute
// an authentication token. The authentication is sent in the body and a
// cookie is set.
type AuthUserHandler struct {
	BaseHandler
}

// AuthUserReq contains user credentials
type AuthUserReq struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// AuthUserResp contains the created authentication token
type AuthUserResp struct {
	AuthToken string    `json:"auth_token"`
	Expires   time.Time `json:"expires"`
}

// ServeHTTP authenticates the user
func (h AuthUserHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Read body
	var authReq AuthUserReq
	if err := DecodeAndValidate(r.Body, &authReq); err != nil {
		h.WriteErr(w, -1, fmt.Errorf("failed to read body"), err)
		return
	}

	// Get user by email
	user := User{Email: authReq.Email}
	if err := h.db.First(&user).Error; gorm.IsRecordNotFoundError(err) {
		h.WriteErr(w, http.StatusNotFound, fmt.Errorf("no user found "+
			"with email", err), nil)
		return
	}

	// Verify password
	err := argonpass.Verify(authReq.Password, user.PasswordHash)
	if err != nil {
		h.WriteErr(w, http.StatusUnauthorized,
			fmt.Errorf("incorrect password"), err)
		return
	}

	// Build JWT authentication token
	tokenExpires := time.Now().Add(14 * 24 * time.Hour)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": user.ID,
		"exp": tokenExpires.Unix(),
	})
	tokenStr, err := token.SignedString(h.cfg.JWTSecret)
	if err != nil {
		h.WriteErr(w, -1, nil, fmt.Errorf("failed to sign authentication "+
			"token JWT: %s", err))
		return
	}

	// Send auth token response
	http.SetCookie(w, &http.Cookie{
		Name:    AuthTokenCookie,
		Value:   tokenStr,
		Expires: tokenExpires,
		Secure:  true,
	})

	h.WriteJSON(w, -1, AuthUserResp{
		AuthToken: tokenStr,
		Expires:   tokenExpires,
	})
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
			cfg: cfg,
		}

		router := mux.NewRouter()
		router.Handle("/api/v0/users", CreateUserHandler{
			BaseHandler: baseHdlr.GetChild("create user"),
		}).Methods("POST")
		router.Handle("/api/v0/users/auth", AuthUserHandler{
			BaseHandler: baseHdlr.GetChild("auth user"),
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
