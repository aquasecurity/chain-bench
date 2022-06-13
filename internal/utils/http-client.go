package utils

import (
	"context"
	"net/http"

	"golang.org/x/oauth2"
)

func GetHttpClient(token string) *http.Client {
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: token},
	)
	hc := oauth2.NewClient(context.TODO(), ts)
	return hc
}
