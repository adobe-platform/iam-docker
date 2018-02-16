package msi

import (
	"encoding/json"
	"github.com/Sirupsen/logrus"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
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
	log            = logrus.WithField("prefix", "msi")
	msiEndpointEnv = os.Getenv("MSI_ENDPOINT")
)

func GetToken(resource string, msiIdentity string) (string, error) {

	logger := log.WithFields(logrus.Fields{
		"resource":    resource,
		"msiIdentity": msiIdentity,
	})

	logger.Info("Got request for msi token")
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
	msi_parameters := url.Values{}
	msi_parameters.Add("resource", resource)
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
	var token tokenJson
	err = json.Unmarshal(responseBytes, &token)
	if err != nil {
		logger.WithField("error", err.Error()).Warn("Error unmarshalling the response")
		return "", err
	}

	responseString := string(responseBytes[:])
	return responseString, nil
}
