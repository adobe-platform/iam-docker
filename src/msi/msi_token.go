package msi

import (
	"encoding/json"
	"errors"
	"fmt"
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
	realTimeGracePeriod = time.Second * 30
	refreshGracePeriod  = time.Minute * 30
	StorageResource     = "https://storage.azure.com/"
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
	log                   = logrus.WithField("prefix", "msi")
	msiEndpointEnv        = os.Getenv("MSI_ENDPOINT")
	msi_endpoint_url      = msiEndpointEnv
	msiApiVersionEnv      = os.Getenv("MSI_API_VERSION")
	msi_api_version       = msiApiVersionEnv
	msiBackoffIntervalEnv = os.Getenv("MSI_BACKOFF_INTERVAL_MILLI")
	backOffInterval       = 5000
	tokenStore            = make(map[string]map[string]*tokenJson)
	tokenMutex            = &sync.RWMutex{}
)

func init() {
	if msi_endpoint_url == "" {
		msi_endpoint_url = "http://localhost:50342/oauth2/token"
	}
	if msi_api_version == "" {
		msi_api_version = "2018-02-01"
	}
	var err error
	if msiBackoffIntervalEnv != "" {
		backOffInterval, err = strconv.Atoi(msiBackoffIntervalEnv)
		if err != nil {
			// default value 5 seconds
			backOffInterval = 5000
		}
	}
}

func GetToken(resource string, msiIdentity string) (string, error) {
	return FetchToken(resource, msiIdentity, realTimeGracePeriod, false)
}

func RefreshToken(resource string, msiIdentity string) (string, error) {
	return FetchToken(resource, msiIdentity, refreshGracePeriod, true)
}

func FetchToken(resource string, msiIdentity string, gracePeriod time.Duration, bypassCache bool) (string, error) {

	logger := log.WithFields(logrus.Fields{
		"resource":    resource,
		"msiIdentity": msiIdentity,
	})

	responseString := GetTokenFromCache(resource, msiIdentity, gracePeriod)
	if responseString != "" {
		return responseString, nil
	}

	httpStatusCode, responseBytes, err := InvokeTokenRequest(resource, msiIdentity, bypassCache)

	if err != nil {
		return "", err
	}

	// If Rate limit, retry from cache, backoff for some time and retry once again
	if httpStatusCode == 429 {
		logger.WithField("response", string(responseBytes)).Info("Rate limit error from MSI endpoint.")
		// Retry from cache once again
		responseString = GetTokenFromCache(resource, msiIdentity, gracePeriod)
		if responseString != "" {
			logger.Info("Got token from cache after rate limit error from MSI endpoint.")
			return responseString, nil
		}
		// Back-off
		time.Sleep(time.Duration(int64(backOffInterval) * int64(time.Millisecond)))
		// Retry from cache one last time
		responseString = GetTokenFromCache(resource, msiIdentity, gracePeriod)
		if responseString != "" {
			logger.Info("Got token from cache after backoff.")
			return responseString, nil
		}
		logger.Info("Reinvoking MSI endpoint after backoff.")
		httpStatusCode, responseBytes, err = InvokeTokenRequest(resource, msiIdentity, bypassCache)
		if err != nil {
			return "", err
		}
	}

	if httpStatusCode != 200 {
		logger.WithField("response", string(responseBytes)).Warn("Error response from MSI Endpoint.")
		return "", errors.New("Got non-ok http status code from MSI Endpoint: " + string(httpStatusCode))
	}

	// Unmarshall response body into struct
	token := &tokenJson{}
	err = json.Unmarshal(responseBytes, token)
	if err != nil {
		logger.WithField("error", err.Error()).Warn("Error unmarshalling the response.")
		return "", err
	}

	tokenMutex.Lock()
	tokenMap, hasKey := tokenStore[msiIdentity]
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

func InvokeTokenRequest(resource string, msiIdentity string, bypassCache bool) (int, []byte, error) {
	logger := log.WithFields(logrus.Fields{
		"resource":    resource,
		"msiIdentity": msiIdentity,
	})
	// Create HTTP request for MSI token to access Azure Resource Manager
	var msi_endpoint *url.URL
	msi_endpoint, err := url.Parse(msi_endpoint_url)
	if err != nil {
		logger.WithField("error", err.Error()).Warn("Error creating URL.")
		return 0, nil, err
	}
	msi_parameters := url.Values{}
	msi_parameters.Add("resource", resource)
	if bypassCache {
		msi_parameters.Add("bypass_cache", "true")
	}
	msi_parameters.Add("api-version", msi_api_version)
	msi_parameters.Add("client_id", msiIdentity)
	msi_endpoint.RawQuery = msi_parameters.Encode()
	req, err := http.NewRequest("GET", msi_endpoint.String(), nil)
	if err != nil {
		logger.WithField("error", err.Error()).Warn("Error creating HTTP request.")
		return 0, nil, err
	}
	req.Header.Add("Metadata", "true")

	// Call MSI /token endpoint
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		logger.WithField("error", err.Error()).Warn("Error calling token endpoint.")
		return 0, nil, err
	}

	// Pull out response body
	responseBytes, err := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	if err != nil {
		logger.WithField("error", err.Error()).Warn("Error reading response body.")
		return 0, nil, err
	}

	return resp.StatusCode, responseBytes, nil
}

func GetTokenFromCache(resource string, msiIdentity string, gracePeriod time.Duration) string {
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
			logger.WithField("error", err.Error()).Warn("Error parsing the token expiry.")
			// Unlikely error no need to throw
			return ""
		}
		expiresOn := time.Unix(int64(expiresOnNumber), 0)
		if time.Now().Add(gracePeriod).Before(expiresOn) {
			freshFor := expiresOn.Sub(time.Now().Add(gracePeriod))
			logger.Debug("Token is fresh for: " + fmt.Sprintf("%f", freshFor.Seconds()) + " seconds")
			tokenBytes, err := json.Marshal(token)
			if err != nil {
				logger.WithField("error", err.Error()).Warn("Error marshaling the token json.")
				// Unlikely error no need to throw
				return ""
			}
			return string(tokenBytes[:])
		}
		logger.Info("Token is stale, refreshing.")
	} else {
		logger.Info("Token is not in the cache, fetching.")
	}
	return ""
}

func RefreshTokens() {
	log.Info("Refreshing MSI Tokens, number of identities: " + strconv.Itoa(len(tokenStore)))
	tokenMutex.RLock()
	identities := make(map[string][]string, len(tokenStore))
	for identity, tokenMap := range tokenStore {
		identities[identity] = make([]string, len(tokenMap))
		count := 0
		for resource, _ := range tokenMap {
			identities[identity][count] = resource
			count++
		}
	}
	tokenMutex.RUnlock()

	for msiIdentity, resources := range identities {
		for _, resource := range resources {
			_, err := RefreshToken(resource, msiIdentity)
			if err != nil {
				log.WithFields(logrus.Fields{
					"msiIdentity": msiIdentity,
					"error":       err.Error(),
				}).Warn("Unable to refresh token")
			}
		}
	}
	log.Info("Done refreshing MSI tokens")
}
