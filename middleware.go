package pweb

import (
	"context"
	"encoding/json"
	"errors"
	"expvar"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"time"

	"runtime/debug"

	jwt "github.com/golang-jwt/jwt/v4"
	"github.com/golang-jwt/jwt/v4/request"
	"github.com/phil-inc/plog/logging"
	"github.com/zserge/metric"
)

type body struct {
	Key string
}
type params struct {
	Key string
}

// Body key for request body
var Body = body{Key: "Body"}

//Params key for params
var Params = params{Key: "Params"}

// Errors represents json errors
type Errors struct {
	Errors []*Error `json:"errors"`
}

// Response response interface
type Response interface {
	Write(w http.ResponseWriter, r *http.Request)
}

// Error represents the API level error for the client apps
type Error struct {
	ID     string `json:"id"`
	Status int    `json:"status"`
	Title  string `json:"title"`
	Detail string `json:"detail"`
}

//ErrorHandler handler for all the middelware errors
type ErrorHandler interface {
	HandleError(r *http.Request, err error)
}

//CustomTokenValidator handler for any custom token validation for the application
type CustomTokenValidator interface {
	IsValid(r *http.Request, userID, rawToken string, claims jwt.MapClaims) bool
}

var (
	// UnAuthorized resource not found error
	UnAuthorized = &Error{"un_authorized", 401, "Request UnAuthorized", "Request must be authorized"}
	// Forbidden resource not found error
	Forbidden = &Error{"forbidden", 403, "Request Forbidden", "Request Forbidden"}
	// ErrNotFound resource not found error
	ErrNotFound = &Error{"not_found", 404, "Not found", "Data not found"}
	// ErrBadRequest bad request error
	ErrBadRequest = &Error{"bad_request", 400, "Bad request", "Request body is not well-formed. It must be JSON."}
	// ErrUnsupportedMediaType error
	ErrUnsupportedMediaType = &Error{"not_supported", 405, "Not supported", "Unsupported media type"}
	// ErrInternalServer error to represent server errors
	ErrInternalServer = &Error{"internal_server_error", 500, "Internal Server Error", "Something went wrong."}
)

var logger = logging.GetContextLogger("middleware")

// APIKeyAuth basically checks the authorization header for API Key
func APIKeyAuth(ctx context.Context, e ErrorHandler, apiKey string) func(http.Handler) http.Handler {
	m := func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			key, err := extractAPIKeyFromAuthHeader(r)
			if err != nil {
				msg := GetLogWithRequestDetails(r, fmt.Sprintf("Invalid authorization header: %s", err))
				err = errors.New(msg)
				e.HandleError(r, err)

				WriteError(w, UnAuthorized)
			} else {
				if key != apiKey {
					msg := GetLogWithRequestDetails(r, "Invalid API Key. Unauthorized access")
					e.HandleError(r, errors.New(msg))

					WriteError(w, UnAuthorized)
				} else {
					// Delegate request to the given handle
					next.ServeHTTP(w, r)
				}
			}
		}

		return http.HandlerFunc(fn)
	}

	return m
}

// JWTAuthWithCustomValidator checks and validate JWT token with custom validator that can perform application specific checks
func JWTAuthWithCustomValidator(ctx context.Context, securityToken string, v CustomTokenValidator, e ErrorHandler) func(http.Handler) http.Handler {
	m := func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			// check JSON web token data
			claims, err := checkJWT(w, r, v, securityToken)
			if err != nil && err.Error() != "Token is expired" {
				msg := GetLogWithRequestDetails(r, fmt.Sprintf("invalid token: %s", err))
				logger.ErrorPrintf(msg)

				WriteError(w, UnAuthorized)
				return
			}

			// If there was an error, do not continue.
			if next != nil {
				if claims != nil {
					b := context.WithValue(r.Context(), SessionUserKey, claims)
					r = r.WithContext(b)
				}
				next.ServeHTTP(w, r)
			}
		}
		return http.HandlerFunc(fn)
	}

	return m
}

// UserAuthorizationHandler - Check the access of the User
func UserAuthorizationHandler(ctx context.Context, e ErrorHandler) func(http.Handler) http.Handler {
	m := func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			userID := SessionUserID(r)
			if r.Header.Get("X-User-Id") == "" {
				msg := GetLogWithRequestDetails(r, "No Request Header X-User-Id Found in Header of the Request")
				logger.ErrorPrintf(msg)

				WriteError(w, UnAuthorized)
				return
			}

			xUserID := r.Header.Get("X-User-Id")
			if userID != xUserID {
				msg := GetLogWithRequestDetails(r, fmt.Sprintf("Request header X-User-Id does not match the user id in the token. User ID: %s, X User ID: %s", xUserID, userID))
				logger.ErrorPrintf(msg)

				WriteError(w, UnAuthorized)
				return
			}

			if next != nil {
				next.ServeHTTP(w, r)
			}
		}
		return http.HandlerFunc(fn)
	}

	return m
}

// JSONBodyHandler is a middleware to decode the JSON body, then set the body
// into the context.
func JSONBodyHandler(ctx context.Context, v interface{}) func(http.Handler) http.Handler {
	t := reflect.TypeOf(v)
	m := func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			if r.Body == nil {
				WriteError(w, ErrBadRequest)
				return
			}

			val := reflect.New(t).Interface()
			err := json.NewDecoder(r.Body).Decode(val)
			if err != nil {
				logger.ErrorPrintf("Error decoding JSON data. Error: %s", err)
				WriteError(w, ErrBadRequest)
				return
			}

			if next != nil {
				b := context.WithValue(r.Context(), Body, val)
				r = r.WithContext(b)
				next.ServeHTTP(w, r)
			}
		}

		return http.HandlerFunc(fn)
	}

	return m
}

// ResponseHandler handles the response from services
func ResponseHandler(f func(http.ResponseWriter, *http.Request) Response) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		response := f(w, r)
		response.Write(w, r)
	}
}

// RecoverHandler is a deferred function that will recover from the panic,
// respond with a HTTP 500 error and log the panic. When our code panics in production
// (make sure it should not but we can forget things sometimes) our application
// will shutdown. We must catch panics, log them and keep the application running.
// It's pretty easy with Go and our middleware system.
func RecoverHandler(ctx context.Context, e ErrorHandler) func(http.Handler) http.Handler {
	m := func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rr := recover(); rr != nil {
					var err error
					switch x := rr.(type) {
					case string:
						err = errors.New(x)
					case error:
						err = x
					default:
						err = errors.New("Unknown panic")
					}
					if err != nil {
						perr := fmt.Errorf("PANIC: %s", err.Error())
						e.HandleError(r, perr)

						//send stack trace as well
						if etrace := debug.Stack(); etrace != nil {
							etrace := fmt.Errorf("STACKTRACE: %s", debug.Stack())
							e.HandleError(r, etrace)
						}
					}
					http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				}
			}()

			if next != nil {
				next.ServeHTTP(w, r)
			}
		}

		return http.HandlerFunc(fn)
	}

	return m
}

//MetricsHandler collects the different http metrics using go expvar package
func MetricsHandler(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		//start time
		t1 := time.Now()

		// custom ResponseWriter wrapper to capture http status code and response size
		httpResponse := logHTTPResponse{ResponseWriter: w}

		next.ServeHTTP(&httpResponse, r)
		//end time
		t2 := time.Now()

		diff := t2.Sub(t1)
		//response time histogram
		expvar.Get("http:response:time:sec").(metric.Metric).Add(diff.Seconds())

		//HTTP request metrics counters
		expvar.Get("http:request:count").(metric.Metric).Add(1)
		m := strings.ToLower(r.Method)
		k := fmt.Sprintf("http:%s:count", m)
		v := expvar.Get(k)
		if v != nil {
			v.(metric.Metric).Add(1)
		}

		//collect rate count
		counter.Incr(1)

		logPrometheusMetrics(httpResponse, r, diff)
	}

	return http.HandlerFunc(fn)
}

//ContentTypeHandler make sure content type is appplication/json for PUT/POST data
func ContentTypeHandler(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/json" {
			WriteError(w, ErrUnsupportedMediaType)
			return
		}
		next.ServeHTTP(w, r)
	}

	return http.HandlerFunc(fn)
}

// WriteJSON writes resource to the output stream as JSON data.
func WriteJSON(w http.ResponseWriter, resource interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Host-Id", hostName)
	t1 := time.Now()
	err := json.NewEncoder(w).Encode(resource)
	if err != nil {
		logger.ErrorPrintf("Error writing JSON: %s", err)
		WriteError(w, ErrInternalServer)
		return
	}
	//end time
	t2 := time.Now()

	diff := t2.Sub(t1)
	expvar.Get("http:json-parse:time:sec").(metric.Metric).Add(diff.Seconds())
}

// WriteError writes error response
func WriteError(w http.ResponseWriter, err *Error) {
	expvar.Get("http:error:count").(metric.Metric).Add(1)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(err.Status)
	w.Header().Set("X-Host-Id", hostName)
	json.NewEncoder(w).Encode(Errors{[]*Error{err}})
}

//GetLogWithRequestDetails return the log message with request details
func GetLogWithRequestDetails(r *http.Request, msg string) string {
	rIP := GetRemoteIP(r)
	appSrc := r.Header.Get("X-App-Source")
	if appSrc == "" {
		appSrc = "N/A"
	}
	return fmt.Sprintf("%s, METHOD: %s, PATH: %s, Remote IP: %s, App source: %s", msg, r.Method, r.RequestURI, rIP, appSrc)
}

func checkJWT(w http.ResponseWriter, r *http.Request, v CustomTokenValidator, securityToken string) (jwt.MapClaims, error) {
	if r.Method == "OPTIONS" {
		return nil, nil
	}

	// Use the specified token extractor to extract a token from the request
	rawToken, err := extractTokenFromAuthHeader(r)
	// If debugging is turned on, log the outcome
	if err != nil {
		return nil, err
	}
	if rawToken == "" {
		return nil, errors.New("invalid token")
	}

	// Now parse the token
	parsedToken, err := request.ParseFromRequest(r, request.AuthorizationHeaderExtractor, func(token *jwt.Token) (interface{}, error) {
		rsaPublicKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(securityToken))
		if err != nil {
			return nil, err
		}
		return rsaPublicKey, nil
	})

	if err != nil {
		return nil, err
	}

	// Check if the parsed token is valid...
	if !parsedToken.Valid {
		return nil, errors.New("invalid token")
	}

	if claims, ok := parsedToken.Claims.(jwt.MapClaims); ok && parsedToken.Valid {
		userID := claims["uid"].(string)

		if v != nil {
			//give a chance to custom validator if it exists
			if !v.IsValid(r, userID, rawToken, claims) {
				return nil, errors.New("invalid token")
			}
		}

		return claims, nil
	}

	return nil, errors.New("invalid token")
}

// extractAPIKeyFromAuthHeader extract Phil API Key from the header
func extractAPIKeyFromAuthHeader(r *http.Request) (string, error) {
	authHeaderParts, err := getAuthHeaderParts(r)
	if err != nil {
		return "", err
	}
	if len(authHeaderParts) != 2 || strings.ToLower(authHeaderParts[0]) != "philkey" {
		return "", errors.New("Incorrect authorization header format. Invalid API Key")
	}
	return authHeaderParts[1], nil
}

// extractTokenFromAuthHeader is a "TokenExtractor" that takes a give request and extracts
// the JWT token from the Authorization header.
func extractTokenFromAuthHeader(r *http.Request) (string, error) {
	authHeaderParts, err := getAuthHeaderParts(r)
	if err != nil {
		return "", err
	}
	if len(authHeaderParts) != 2 || strings.ToLower(authHeaderParts[0]) != "bearer" {
		return "", errors.New("invalid token")
	}

	return authHeaderParts[1], nil
}

func getAuthHeaderParts(r *http.Request) ([]string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return []string{""}, nil // No error, just no token
	}
	return strings.Split(authHeader, " "), nil
}
