package msi

import (
  "fmt"
  "github.com/Sirupsen/logrus"
  "io/ioutil"
  "net/http"
  "net/url"
  "encoding/json"
)

type tokenJson struct {
  AccessToken string `json:"access_token"`
  RefreshToken string `json:"refresh_token"`
  ExpiresIn string `json:"expires_in"`
  ExpiresOn string `json:"expires_on"`
  NotBefore string `json:"not_before"`
  Resource string `json:"resource"`
  TokenType string `json:"token_type"`
}

var (
  log = logrus.WithField("prefix", "msi")
)


func GetToken(resource string, msiIdentity string) (string, error) {

  logger := log.WithFields(logrus.Fields{
    "resource":       resource,
    "msiIdentity":     msiIdentity,
  })

  logger.Info("Got request for msi token")
    // Create HTTP request for MSI token to access Azure Resource Manager
    var msi_endpoint *url.URL
    msi_endpoint, err := url.Parse("http://localhost:50342/oauth2/token")
    if err != nil {
      logger.WithField("error", err.Error()).Warn("Error creating URL")
      return "", err 
    }
    msi_parameters := url.Values{}
    msi_parameters.Add("resource", resource)
    //msi_parameters.Add("resource", "https://datalake.azure.net/")
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
    if err != nil{
      logger.WithField("error", err.Error()).Warn("Error calling token endpoint")
      return "", err
    }

    // Pull out response body
    responseBytes,err := ioutil.ReadAll(resp.Body)
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

    // Print HTTP response and marshalled response body elements to console TODO Remove these prints
    fmt.Println("Response status:", resp.Status)
    fmt.Println("access_token: ", token.AccessToken)
    fmt.Println("refresh_token: ", token.RefreshToken)
    fmt.Println("expires_in: ", token.ExpiresIn)
    fmt.Println("expires_on: ", token.ExpiresOn)
    fmt.Println("not_before: ", token.NotBefore)
    fmt.Println("resource: ", token.Resource)
    fmt.Println("token_type: ", token.TokenType)
    responseString := string(responseBytes[:])
    return responseString, nil
}

