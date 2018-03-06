package msi

import (
	"encoding/json"
	"github.com/Sirupsen/logrus"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"sync"
	"time"
)

const (
	gracePeriod = time.Second * 30
)

type tokenJson struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    string `json:"expires_in"`
	ExpiresOn    string `json:"expires_on"`
	NotBefore    string `json:"not_before"`
	Resource     string `json:"resource"`
	TokenType    string `json:"token_type"`
}

var (
	log              = logrus.WithField("prefix", "msi")
	msiEndpointEnv   = os.Getenv("MSI_ENDPOINT")
	msiApiVersionEnv = os.Getenv("MSI_API_VERSION")
	tokenStore       = make(map[string]map[string]*tokenJson)
	tokenMutex       = &sync.RWMutex{}
)

func GetToken(resource string, msiIdentity string) (string, error) {

	logger := log.WithFields(logrus.Fields{
		"resource":    resource,
		"msiIdentity": msiIdentity,
	})

	var token *tokenJson
	hasToken := false
	//Look for the cached one
	tokenMutex.RLock()
	tokenMap, hasKey := tokenStore[msiIdentity]
	if hasKey {
		token, hasToken = tokenMap[resource]
	}
	tokenMutex.RUnlock()

	// Return if cached one is still fresh
	if hasToken {
		expiresOnNumber, err := strconv.Atoi(token.ExpiresOn)
		if err != nil {
			logger.WithField("error", err.Error()).Warn("Error parsing the token expiry")
			return "", err
		}
		expiresOn := time.Unix(int64(expiresOnNumber), 0)
		if time.Now().Add(gracePeriod).Before(expiresOn) {
			logger.Debug("token is fresh")
			tokenBytes, err := json.Marshal(token)
			if err != nil {
				logger.WithField("error", err.Error()).Warn("Error marshaling the token json")
				return "", err
			}
			return string(tokenBytes[:]), nil
		}
		logger.Info("token is stale, refreshing")
	} else {
		logger.Info("token is not in the cache, fetching")
	}

	// Create HTTP request for MSI token to access Azure Resource Manager
	var msi_endpoint_url = msiEndpointEnv
	if msi_endpoint_url == "" {
		msi_endpoint_url = "http://localhost:50342/oauth2/token"
	}
	var msi_endpoint *url.URL
	msi_endpoint, err := url.Parse(msi_endpoint_url)
	if err != nil {
		logger.WithField("error", err.Error()).Warn("Error creating URL")
		return "", err
	}
	var msi_api_version = msiApiVersionEnv
	if msi_api_version == "" {
		msi_api_version = "2018-02-01"
	}
	msi_parameters := url.Values{}
	msi_parameters.Add("resource", resource)
	msi_parameters.Add("api-version", msi_api_version)
	msi_parameters.Add("client_id", msiIdentity)
	msi_endpoint.RawQuery = msi_parameters.Encode()
	req, err := http.NewRequest("GET", msi_endpoint.String(), nil)
	if err != nil {
		logger.WithField("error", err.Error()).Warn("Error creating HTTP request")
		return "", err
	}
	req.Header.Add("Metadata", "true")

	// Call MSI /token endpoint
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		logger.WithField("error", err.Error()).Warn("Error calling token endpoint")
		return "", err
	}

	// Pull out response body
	responseBytes, err := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	if err != nil {
		logger.WithField("error", err.Error()).Warn("Error reading response body")
		return "", err
	}

	// Unmarshall response body into struct
	token = &tokenJson{}
	err = json.Unmarshal(responseBytes, token)
	if err != nil {
		logger.WithField("error", err.Error()).Warn("Error unmarshalling the response")
		return "", err
	}

	tokenMutex.Lock()
	tokenMap, hasKey = tokenStore[msiIdentity]
	if !hasKey {
		tokenMap = make(map[string]*tokenJson)
		tokenStore[msiIdentity] = tokenMap
	}
	tokenMap[resource] = token
	tokenMutex.Unlock()

	// For consistency sake, return the json to the extent present in our struct
	tokenBytes, err := json.Marshal(token)
	return string(tokenBytes[:]), nil
}
