package pweb

import (
	"context"
	"errors"
	"expvar"
	"net/http"
	"runtime"
	"strings"
	"time"

	"log"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/julienschmidt/httprouter"
	"github.com/paulbellamy/ratecounter"
	"github.com/zserge/metric"
)

type sessionUser struct {
	Key string
}

var counter *ratecounter.RateCounter

//initialize http metrics
func init() {

	counter = ratecounter.NewRateCounter(1 * time.Minute)

	expvar.Publish("system:uptime", metric.NewCounter("5m1m", "15m1m", "1h1m", "24h1h", "7d1d"))
	go func() {
		for range time.Tick(1 * time.Minute) {
			expvar.Get("system:uptime").(metric.Metric).Add(float64(60))
		}
	}()

	// Some Go internal metrics
	numgoroutine := "system:go:numgoroutine"
	numcgocall := "system:go:numcgocall"
	numcpu := "system:go:numcpu"
	alloc := "system:go:alloc"
	alloctotal := "system:go:alloctotal"

	frames := []string{"5m1m", "15m1m", "1h1m", "24h1h", "7d1d"}

	expvar.Publish(numgoroutine, metric.NewGauge(frames...))
	expvar.Publish(numcgocall, metric.NewGauge(frames...))
	expvar.Publish(numcpu, metric.NewGauge(frames...))
	expvar.Publish(alloc, metric.NewGauge(frames...))
	expvar.Publish(alloctotal, metric.NewGauge(frames...))
	go func() {
		for range time.Tick(5 * time.Minute) {
			m := &runtime.MemStats{}
			runtime.ReadMemStats(m)

			expvar.Get(numgoroutine).(metric.Metric).Add(float64(runtime.NumGoroutine()))
			expvar.Get(numcgocall).(metric.Metric).Add(float64(runtime.NumCgoCall()))
			expvar.Get(numcpu).(metric.Metric).Add(float64(runtime.NumCPU()))
			expvar.Get(alloc).(metric.Metric).Add(float64(m.Alloc) / 1000000)
			expvar.Get(alloctotal).(metric.Metric).Add(float64(m.TotalAlloc) / 1000000)
		}
	}()

	// A counter that keeps different HTTP request counts for 7 days, 24 hours, 1 hour, 15 minutes, 5 minutes of time with different precision:
	expvar.Publish("http:get:count", metric.NewCounter(frames...))
	expvar.Publish("http:post:count", metric.NewCounter(frames...))
	expvar.Publish("http:put:count", metric.NewCounter(frames...))
	expvar.Publish("http:delete:count", metric.NewCounter(frames...))
	expvar.Publish("http:request:count", metric.NewCounter(frames...))
	expvar.Publish("http:error:count", metric.NewCounter(frames...))

	//request rate per minute
	expvar.Publish("http:request:rate", metric.NewCounter(frames...))

	//response time
	expvar.Publish("http:response:time", metric.NewGauge("5m1s", "15m1s", "1h1m", "24h1h", "7d1d"))
}

// SessionUserKey key for context
var SessionUserKey = sessionUser{Key: "SessionUser"}

// PhilRouter wraps httprouter, which is non-compatible with http.Handler to make it
// compatible by implementing http.Handler into a httprouter.Handler function.
type PhilRouter struct {
	Ctx            context.Context
	AllowedDomains string
	r              *httprouter.Router
}

// NewPhilRouter returns new PhilRouter which wraps the httprouter
func NewPhilRouter(ctx context.Context) *PhilRouter {
	return &PhilRouter{ctx, "*", httprouter.New()}
}

//SetAllowedDomains update the list of allowed domains for CORS
func (s *PhilRouter) SetAllowedDomains(domains string) {
	s.AllowedDomains = domains
}

//EnableHTTPMetrics enable http metrics collections. In order for these 2 work and collect pweb http metrics
//pweb.MetricsHandler should be added in the handler chain
//metrics collection is based on https://zserge.com/blog/metrics.html
func (s *PhilRouter) EnableHTTPMetrics() {
	//Expose raw metrics data
	s.Get("/debug/vars", expvar.Handler())
	//Expose opinionated web UI for metrics
	s.Get("/debug/metrics", metric.Handler(metric.Exposed))
}

func (s *PhilRouter) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	origin := req.Header.Get("Origin")
	if origin == "" {
		w.Header().Set("Access-Control-Allow-Origin", "*")
	} else {
		corsList := s.AllowedDomains
		if strings.Contains(corsList, origin) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		} else {
			WriteError(w, Forbidden)
			return
		}
	}

	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, X-Requested-With, X-App-Source, X-Request-Id, X-User-Id, Strict-Transport-Security")
	if req.Method == "OPTIONS" {
		w.(http.Flusher).Flush()
	}
	//HSTS is an opt-in security enhancement that instructs the browser to force all communication over HTTPS through a special response header
	w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	s.r.ServeHTTP(w, req)
}

// wrapper around httprouter's HTTP methods to make it compatible with http.Handler interface

// Get wraps httprouter's GET function
func (s *PhilRouter) Get(path string, handler http.Handler) {
	s.r.GET(path, wrapHandler(s.Ctx, handler))
}

// Post wraps httprouter's POST function
func (s *PhilRouter) Post(path string, handler http.Handler) {
	s.r.POST(path, wrapHandler(s.Ctx, handler))
}

// Put wraps httprouter's PUT function
func (s *PhilRouter) Put(path string, handler http.Handler) {
	s.r.PUT(path, wrapHandler(s.Ctx, handler))
}

// Delete wraps httprouter's DELETE function
func (s *PhilRouter) Delete(path string, handler http.Handler) {
	s.r.DELETE(path, wrapHandler(s.Ctx, handler))
}

// wrapHandler - The problem with httprouter is its non-compatibility with
// http.Handler. To make it compatible with existing middlewares and contexts.
// this function wraps our middleware stack – implementing http.Handler – into
// a httprouter.Handler function.
func wrapHandler(ctx context.Context, h http.Handler) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		//instead of passing extra params to handler function use context
		if ps != nil {
			ctxParams := context.WithValue(r.Context(), Params, ps)
			r = r.WithContext(ctxParams)
		}
		h.ServeHTTP(w, r)
	}
}

// ErrMissingRequiredData error to represent missing data error
var ErrMissingRequiredData = errors.New("missing required data")

//ErrNotRecognized error for any unrecognized client
var ErrNotRecognized = errors.New("not recognized")

//ErrForbidden 403
var ErrForbidden = errors.New("forbidden")

// HTMLResponse response as HTML data
type HTMLResponse struct {
	HTML []byte
}

// Write - Write an HTML response
func (res HTMLResponse) Write(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.Write(res.HTML)
}

// XMLResponse response as XML
type XMLResponse struct {
	XML []byte
}

// Write - Write an XML response
func (res XMLResponse) Write(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/xml")
	w.Write(res.XML)
}

// CSVResponse response as CSV data
type CSVResponse struct {
	CSV []byte
}

// Write - Write an CSV response
func (res CSVResponse) Write(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/csv")
	w.Write(res.CSV)
}

// APIResponse response data representation for API
type APIResponse struct {
	Error  string      `json:"error,omitempty"`
	Status string      `json:"status,omitempty"`
	Data   interface{} `json:"data,omitempty"`
}

// Write - Reponse interface implementation
func (res APIResponse) Write(w http.ResponseWriter, r *http.Request) {
	if res.Status == "ERROR" {
		log.Printf("[ERROR][API][PATH: %s]:: Error handling request. ERROR: %s. User agent: %s", r.RequestURI, res.Error, r.Header.Get("User-Agent"))
	}
	WriteJSON(w, res)
}

// DataResponse creates new API data response using the resource
func DataResponse(data interface{}) APIResponse {
	return APIResponse{Error: "", Status: "OK", Data: data}
}

// StringErrorResponse constructs error response based on input
func StringErrorResponse(err string) APIResponse {
	return APIResponse{Error: err, Status: "ERROR", Data: nil}
}

//ErrorResponse constructs error response from the API
func ErrorResponse(err error) APIResponse {
	return APIResponse{Error: err.Error(), Status: "ERROR", Data: nil}
}

// RequestBody returns the request body
func RequestBody(r *http.Request) interface{} {
	return r.Context().Value(Body)
}

// SessionUserID returns user id of the current session
func SessionUserID(r *http.Request) string {
	if jwtClaims, ok := r.Context().Value(SessionUserKey).(jwt.MapClaims); ok {
		return jwtClaims["uid"].(string)
	}
	return ""
}

// UserRoles current user roles
func UserRoles(r *http.Request) []string {
	if jwtClaims, ok := r.Context().Value(SessionUserKey).(jwt.MapClaims); ok {
		return jwtClaims["uid"].([]string)
	}
	return make([]string, 0)
}

// QueryParamByName returns the request param by name
func QueryParamByName(name string, r *http.Request) string {
	return r.URL.Query().Get(name)
}

// QueryParamsByName returns the request param by name
func QueryParamsByName(name string, r *http.Request) []string {
	values := r.URL.Query()
	return values[name]
}

// ParamByName returns the request param by name
func ParamByName(name string, r *http.Request) string {
	params := r.Context().Value(Params).(httprouter.Params)
	return params.ByName(name)
}

//Authorize checks if given request is authorized
func Authorize(w http.ResponseWriter, r *http.Request) {
	sid := SessionUserID(r)
	uid := ParamByName("uid", r)

	if sid != uid {
		WriteError(w, Forbidden)
	}
}
