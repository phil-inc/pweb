package pweb

import (
	"fmt"
	"net/http"
	"regexp"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var quantileMap = map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.95: 0.005, 0.99: 0.001, 1.0: 0.0}

var (
	apiResponseStatusCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "api_response_status_counter",
			Help: "Counts response status for api endpoints",
		},
		[]string{"endpoint", "status"},
	)
	apiResponseDuration = promauto.NewSummaryVec(
		prometheus.SummaryOpts{
			Name:       "api_response_duration",
			Help:       "Response time for api endpoints",
			Objectives: quantileMap,
		},
		[]string{"endpoint", "method"},
	)
	apiResponseSize = promauto.NewSummaryVec(
		prometheus.SummaryOpts{
			Name:       "api_response_size",
			Help:       "Response size for api endpoints",
			Objectives: quantileMap,
		},
		[]string{"endpoint", "method"},
	)
)

func sanitizeURL(url string) string {
	removeParams := regexp.MustCompile(`\?.*`)
	replaceObjectID := regexp.MustCompile(`\/[0-9a-fA-F]{24}\/`)
	str := removeParams.ReplaceAllString(url, "")
	str = replaceObjectID.ReplaceAllString(str, "/:id/")
	return str
}

// custom ResponseWriter wrapper to capture http status code and response size
type logHTTPResponse struct {
	http.ResponseWriter
	status int
	length int
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

func logPrometheusMetrics(httpResponse logHTTPResponse, r *http.Request, responseDuration time.Duration) {

	url := sanitizeURL(r.RequestURI)

	// response latency
	apiResponseDuration.With(prometheus.Labels{"endpoint": url, "method": r.Method}).Observe(float64(responseDuration.Milliseconds()))

	// log each http status code and buckets (2xx, 3xx, etc)
	statusCode := fmt.Sprintf("%d", httpResponse.status)
	statusBucket := fmt.Sprintf("%cxx", statusCode[0])

	// individual urls
	apiResponseStatusCounter.With(prometheus.Labels{"endpoint": url, "status": statusCode}).Inc()
	apiResponseStatusCounter.With(prometheus.Labels{"endpoint": url, "status": statusBucket}).Inc()

	// count for all urls
	apiResponseStatusCounter.With(prometheus.Labels{"endpoint": "all", "status": statusCode}).Inc()
	apiResponseStatusCounter.With(prometheus.Labels{"endpoint": "all", "status": statusBucket}).Inc()

	// response size
	apiResponseSize.With(prometheus.Labels{"endpoint": url, "method": r.Method}).Observe(float64(httpResponse.length))

}
