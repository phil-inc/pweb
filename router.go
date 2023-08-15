package pweb

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/NYTimes/gziphandler"
	"github.com/golang-jwt/jwt/v4"
	"github.com/julienschmidt/httprouter"
	logger "github.com/phil-inc/plog-ng/pkg/core"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	httptrace "gopkg.in/DataDog/dd-trace-go.v1/contrib/julienschmidt/httprouter"
)

type sessionUser struct {
	Key string
}

var hostName string

// initialize http metrics
func init() {
	hostName, _ = os.Hostname()
}

// SessionUserKey key for context
var SessionUserKey = sessionUser{Key: "SessionUser"}

var compressor func(http.Handler) http.Handler

// PhilRouter wraps httprouter, which is non-compatible with http.Handler to make it
// compatible by implementing http.Handler into a httprouter.Handler function.
type PhilRouter struct {
	Ctx            context.Context
	AllowedDomains string
	gzip           bool
	r              *httptrace.Router
}

// NewPhilRouter returns new PhilRouter which wraps the httprouter
func NewPhilRouter(ctx context.Context) *PhilRouter {
	return &PhilRouter{ctx, "*", false, httptrace.New()}
}

// SetAllowedDomains update the list of allowed domains for CORS
func (s *PhilRouter) SetAllowedDomains(domains string) {
	s.AllowedDomains = domains
}

// EnableGzip enable gzip compression for given level in the range from no compression to best
//
//	 NoCompression      = 0
//		BestSpeed          = 1
//		BestCompression    = 9
func (s *PhilRouter) EnableGzip(level int) {
	c, err := gziphandler.NewGzipLevelHandler(level)
	if err == nil {
		compressor = c
		s.gzip = true
	}
}

// EnablePrometheusMetrics enable metrics for prometheus
func (s *PhilRouter) EnablePrometheusMetrics() {
	//Expose metrics data for prometheus
	s.Get("/metrics", promhttp.Handler())
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
	w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, X-Requested-With, X-App-Source, X-Request-Id, X-User-Id, Strict-Transport-Security, X-Forwarded-For, X-Real-Ip, X-Phil-Canary, X-Phil-Debug, Browser-User-Agent")
	w.Header().Set("Access-Control-Max-Age", "7200")
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
	if compressor != nil && s.gzip {
		s.r.GET(path, wrapHandler(s.Ctx, compressor(handler)))
	} else {
		s.r.GET(path, wrapHandler(s.Ctx, handler))
	}
}

// Head wraps httprouter's HEAD function
func (s *PhilRouter) Head(path string, handler http.Handler) {
	s.r.HEAD(path, wrapHandler(s.Ctx, handler))
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

// ErrNotRecognized error for any unrecognized client
var ErrNotRecognized = errors.New("not recognized")

// ErrForbidden 403
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
		logger.Errorf("[API][PATH: %s]:: Error handling request. ERROR: %s. User agent: %s", r.RequestURI, res.Error, r.Header.Get("User-Agent"))
	}

	if res.Status == "WARN" {
		logger.Warnf("[API][PATH: %s]:: Issue while handling request. WARN: %s. User agent: %s", r.RequestURI, res.Error, r.Header.Get("User-Agent"))
	}
	WriteJSON(w, res)
}

// ImageDataResponse - response which has the header and byte data for an image.
type ImageDataResponse struct {
	ImageType string // set to '*' for variable image types.
	ImageData []byte
}

// Write - sets the "Content-Type" header and returns the image data.
func (res ImageDataResponse) Write(w http.ResponseWriter, r *http.Request) {
	contentType := fmt.Sprintf("image/%s", res.ImageType)

	w.Header().Set("Content-Type", contentType)
	w.Write(res.ImageData)
}

// PDFDataResponse - response which has the header and byte data for a PDF.
type PDFDataResponse struct {
	ContentDisposition string // PDFResponse() sets a default for this.
	PDFData            []byte
}

// Write - sets the "Content-Disposition" header and returns the PDF data.
func (res PDFDataResponse) Write(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", res.ContentDisposition)
	w.Write(res.PDFData)
}

// DataResponse creates new API data response using the resource
func DataResponse(data interface{}) APIResponse {
	return APIResponse{Error: "", Status: "OK", Data: data}
}

// StringErrorResponse constructs error response based on input
func StringErrorResponse(err string) APIResponse {
	return APIResponse{Error: err, Status: "ERROR", Data: nil}
}

// ErrorResponse constructs error response from the API
func ErrorResponse(err error) APIResponse {
	return APIResponse{Error: err.Error(), Status: "ERROR", Data: nil}
}

// ImageResponse constructs an image response from a content type and image data.
func ImageResponse(imageType string, data []byte) ImageDataResponse {
	return ImageDataResponse{ImageType: imageType, ImageData: data}
}

// PDFResponse constructs a PDF response from a content-disposition and PDF data.
func PDFResponse(contentDisposition string, data []byte) PDFDataResponse {
	if contentDisposition == "" {
		contentDisposition = "attachment; filename=filename.pdf" // default to sending as attachment
	}

	return PDFDataResponse{ContentDisposition: contentDisposition, PDFData: data}
}

// PaginatedDataResponse response data in paginated form
type PaginatedDataResponse struct {
	Error       string      `json:"error,omitempty"`
	Status      string      `json:"status,omitempty"`
	Total       int         `json:"total,omitempty"`
	PerPage     int         `json:"perPage,omitempty"`
	CurrentPage int         `json:"currentPage,omitempty"`
	TotalPages  int         `json:"totalPages,omitempty"`
	Data        interface{} `json:"data,omitempty"`
}

// Write - Reponse interface implementation
func (res PaginatedDataResponse) Write(w http.ResponseWriter, r *http.Request) {
	if res.Status == "ERROR" {
		logger.Errorf("[API][PATH: %s]:: Error handling request. ERROR: %s. User agent: %s", r.RequestURI, res.Error, r.Header.Get("User-Agent"))
	}

	if res.Status == "WARN" {
		logger.Warnf("[API][PATH: %s]:: Issue while handling request. WARN: %s. User agent: %s", r.RequestURI, res.Error, r.Header.Get("User-Agent"))
	}
	WriteJSON(w, res)
}

// PaginatedResponse created data response with total pages
func PaginatedResponse(data interface{}, total, perPage, currentPage, totalPages int) PaginatedDataResponse {
	return PaginatedDataResponse{Error: "", Status: "OK", Total: total, PerPage: perPage, CurrentPage: currentPage, TotalPages: totalPages, Data: data}
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

// Authorize checks if given request is authorized
func Authorize(w http.ResponseWriter, r *http.Request) {
	sid := SessionUserID(r)
	uid := ParamByName("uid", r)

	if sid != uid {
		WriteError(w, Forbidden)
	}
}

// GetRemoteIP returns the IP address of the client sending the request. It walks backwards through the number of ip
// addresses by the number of proxies you have in your environment to the internet. That way, you will be adverse to
// any mucking with the X-Forwarded-For header by the client
func GetRemoteIP(r *http.Request) string {
	for _, h := range []string{"X-Forwarded-For", "X-Real-Ip"} {
		addresses := strings.Split(r.Header.Get(h), ",")
		// march from right to left until we get a public address
		// that will be the address right before our proxy.
		for i := len(addresses) - 1; i >= 0; i-- {
			ip := strings.TrimSpace(addresses[i])
			// header can contain spaces too, strip those out.
			realIP := net.ParseIP(ip)
			if !realIP.IsGlobalUnicast() || isPrivateSubnet(realIP) {
				// bad address, go to next
				continue
			}

			return ip
		}
	}

	return ""
}

// ipRange - a structure that holds the start and end of a range of ip addresses
type ipRange struct {
	start net.IP
	end   net.IP
}

// inRange - check to see if a given ip address is within a range given
func inRange(r ipRange, ipAddress net.IP) bool {
	// strcmp type byte comparison
	if bytes.Compare(ipAddress, r.start) >= 0 && bytes.Compare(ipAddress, r.end) < 0 {
		return true
	}
	return false
}

// IP ranges to filter out private sub-nets, as well as multi-cast address space, and localhost address space
// Reference - https://whatismyipaddress.com/private-ip
var privateRanges = []ipRange{
	{
		start: net.ParseIP("10.0.0.0"),
		end:   net.ParseIP("10.255.255.255"),
	},
	{
		start: net.ParseIP("100.64.0.0"),
		end:   net.ParseIP("100.127.255.255"),
	},
	{
		start: net.ParseIP("172.16.0.0"),
		end:   net.ParseIP("172.31.255.255"),
	},
	{
		start: net.ParseIP("192.0.0.0"),
		end:   net.ParseIP("192.0.0.255"),
	},
	{
		start: net.ParseIP("192.168.0.0"),
		end:   net.ParseIP("192.168.255.255"),
	},
	{
		start: net.ParseIP("198.18.0.0"),
		end:   net.ParseIP("198.19.255.255"),
	},
}

// isPrivateSubnet - check to see if this ip is in a private subnet
func isPrivateSubnet(ipAddress net.IP) bool {
	// my use case is only concerned with ipv4 atm
	if ipCheck := ipAddress.To4(); ipCheck != nil {
		// iterate over all our ranges
		for _, r := range privateRanges {
			// check if this ip is in a private range
			if inRange(r, ipAddress) {
				return true
			}
		}
	}
	return false
}
