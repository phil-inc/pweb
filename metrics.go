package pweb

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/julienschmidt/httprouter"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// custom ResponseWriter wrapper to capture http status code and response size
type logHTTPResponse struct {
	http.ResponseWriter
	status int
	length int
}

var quantileMap = map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.95: 0.005, 0.99: 0.001, 1.0: 0.0}

var (
	requestCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Counts total request",
		},
		[]string{"endpoint", "method", "status"},
	)
	responseDuration = promauto.NewSummaryVec(
		prometheus.SummaryOpts{
			Name:       "http_request_duration_seconds",
			Help:       "Total duration for request",
			Objectives: quantileMap,
		},
		[]string{"endpoint", "method", "status"},
	)
	responseBytes = promauto.NewSummaryVec(
		prometheus.SummaryOpts{
			Name:       "http_request_response_bytes",
			Help:       "Response size for endpoints",
			Objectives: quantileMap,
		},
		[]string{"endpoint", "method", "status"},
	)
)

func sanitizeURL(r *http.Request) string {
	url := r.RequestURI
	removeQuery := regexp.MustCompile(`\?.*`)
	str := removeQuery.ReplaceAllString(url, "")
	vals := r.Context().Value(Params)
	if vals != nil {
		params := vals.(httprouter.Params)
		for _, p := range params {
			str = strings.Replace(str, p.Value, fmt.Sprintf(":%s", p.Key), 1)
		}
	}

	return str
}

func (w *logHTTPResponse) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *logHTTPResponse) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = 200
	}
	n, err := w.ResponseWriter.Write(b)
	w.length += n
	return n, err
}

func logPrometheusMetrics(httpResponse logHTTPResponse, r *http.Request, respDuration time.Duration) {

	url := sanitizeURL(r)
	statusCode := fmt.Sprintf("%d", httpResponse.status)

	responseDuration.With(prometheus.Labels{"endpoint": url, "method": r.Method, "status": statusCode}).Observe(float64(respDuration.Seconds()))

	requestCounter.With(prometheus.Labels{"endpoint": url, "method": r.Method, "status": statusCode}).Inc()

	responseBytes.With(prometheus.Labels{"endpoint": url, "method": r.Method, "status": statusCode}).Observe(float64(httpResponse.length))

}
