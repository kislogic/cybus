package ipgeolocation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"path"

	"golang.org/x/time/rate"
)

type apiConfig struct {
	host string
	path string
}

var geoLocationAPI = &apiConfig{
	host: "https://api.ipgeolocation.io",
	path: "/ipgeo",
}

// GeoLocationClient abstracts communication with https://ipgeolocation.io/ .
type GeoLocationClient struct {
	baseURL     string
	apiKey      string
	rateLimiter *rate.Limiter
	logger      *log.Logger
	client      *http.Client
}

// NewIPGeoLocationClient creates *GeolocationClient.
func NewIPGeoLocationClient(apiKey string, baseURL string, client *http.Client, rps int, logger *log.Logger) (*GeoLocationClient, error) {

	if apiKey == "" {
		return nil, errors.New("ipgeolocation: provided api key is empty")
	}
	if client == nil {
		return nil, errors.New("ipgeolocation: provided http client is nil")
	}

	return &GeoLocationClient{
		apiKey:      apiKey,
		baseURL:     baseURL,
		client:      client,
		logger:      logger,
		rateLimiter: rate.NewLimiter(rate.Limit(rps), rps),
	}, nil
}

// GeoLocationResponse is a response structure from GetIPGeo
type GeoLocationResponse struct {
	CountryName string `json:"country_name"`
	City        string `json:"city"`
}

func (c GeoLocationClient) awaitRateLimiter(ctx context.Context) error {
	if c.rateLimiter == nil {
		return nil
	}
	return c.rateLimiter.Wait(ctx)
}

// GetIPGeo returns country name among with a city by given ip.
func (c *GeoLocationClient) GetIPGeo(ctx context.Context, ip string) (*GeoLocationResponse, error) {

	if err := c.awaitRateLimiter(ctx); err != nil {
		return nil, err
	}

	if net.ParseIP(ip) == nil {
		return nil, errors.New("ipgeolocation: problem while trying to parse ip")
	}

	host := geoLocationAPI.host
	if c.baseURL != "" {
		host = c.baseURL
	}

	u, err := url.Parse(host)
	if err != nil {
		return nil, fmt.Errorf("ipgeolocation: problem while trying to parse host: %w", err)
	}
	u.Path = path.Join(u.Path, geoLocationAPI.path)

	q := make(url.Values, 2)
	q.Set("apiKey", c.apiKey)
	q.Set("ip", ip)

	u.RawQuery = q.Encode()
	uri := u.String()

	response := GeoLocationResponse{}
	if err := c.getJSON(ctx, uri, &response); err != nil {
		return nil, fmt.Errorf("ipgeolocation: problem with http request: %w", err)
	}

	return &response, nil
}

func (c *GeoLocationClient) getJSON(ctx context.Context, uri string, ptrInterface interface{}) error {

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return fmt.Errorf("http client error occured while creating new request: %w", err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("problem while performing http request: %w", err)
	}
	defer func(body io.ReadCloser) {
		err := body.Close()
		if err != nil {
			c.logf("problem closing resp body: %v", err)
		}
	}(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("http status code is not ok, it is %d", resp.StatusCode)
	}
	if err = json.NewDecoder(resp.Body).Decode(ptrInterface); err != nil {
		return fmt.Errorf("problem while decoding json: %w", err)
	}
	return nil
}

func (c *GeoLocationClient) logf(format string, args ...interface{}) {
	if lg := c.logger; lg != nil {
		lg.Printf(format, args...)
	}
}
