package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
)

type Post struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

func main() {
	tokenURL := os.Getenv("JWT_TOKEN_URL")
	if tokenURL == "" {
		panic("JWT_TOKEN_URL must be set")
	}

	clientID := os.Getenv("JWT_CLIENT_ID")
	if clientID == "" {
		panic("JWT_CLIENT_ID must be set")
	}

	clientSecret := os.Getenv("JWT_CLIENT_SECRET")
	if clientSecret == "" {
		panic("JWT_CLIENT_SECRET must be set")
	}

	scope := os.Getenv("JWT_SCOPE")
	if scope == "" {
		panic("JWT_SCOPE must be set")
	}

	body := []byte(fmt.Sprintf("grant_type=client_credentials&client_id=%s&client_secret=%s&scope=%s", clientID, clientSecret, scope))

	r, err := http.NewRequest("POST", tokenURL, bytes.NewBuffer(body))
	if err != nil {
		panic(err)
	}

	r.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	res, err := client.Do(r)
	if err != nil {
		panic(err)
	}

	defer res.Body.Close()

	post := &Post{}
	derr := json.NewDecoder(res.Body).Decode(post)
	if derr != nil {
		panic(derr)
	}

	fmt.Println("AccessToken:", post.AccessToken)
	fmt.Println("ExpiresIn:", post.ExpiresIn)
	fmt.Println("TokenType:", post.TokenType)
}
