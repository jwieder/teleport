/*
Copyright 2021 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package auth

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"regexp"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/trace"
)

const (
	expectedSTSIdentityRequestBody = "Action=GetCallerIdentity&Version=2011-06-15"
	stsHost                        = "sts.amazonaws.com"
	challengeHeaderKey             = "X-Teleport-Challenge"
	authHeaderKey                  = "Authorization"
)

var validAuthHeader = regexp.MustCompile(`^\S+ Credential=\S+ SignedHeaders=\S*x-teleport-challenge`)

func validateSTSIdentityRequest(req *http.Request, challenge string) error {
	if req.Host != stsHost {
		return trace.AccessDenied("sts identity request is for unknown host %q", req.Host)
	}

	if req.Method != http.MethodPost {
		return trace.AccessDenied("sts identity request method %q does not match expected method %q", req.RequestURI, http.MethodPost)
	}

	if req.Header.Get(challengeHeaderKey) != challenge {
		return trace.AccessDenied("sts identity request does not include challenge header or it does not match")
	}

	authHeader := req.Header.Get(authHeaderKey)
	if !validAuthHeader.MatchString(authHeader) {
		return trace.AccessDenied("sts identity request Authorization header is invalid")
	}

	body, err := io.ReadAll(req.Body)
	if err != nil {
		return trace.Wrap(err)
	}

	if !bytes.Equal([]byte(expectedSTSIdentityRequestBody), body) {
		return trace.BadParameter("sts request body %q does not equal expected %q", string(body), expectedSTSIdentityRequestBody)
	}

	req.Body = io.NopCloser(bytes.NewBuffer(body))

	return nil
}

func parseSTSRequest(req []byte) (*http.Request, error) {
	httpReq, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(req)))
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// unset RequestURI and set req.URL instead (quirk of using http.ReadRequest)
	httpReq.RequestURI = ""
	httpReq.URL = &url.URL{
		Scheme: "https",
		Host:   stsHost,
	}
	return httpReq, nil
}

type stsIdentityResponse struct {
	GetCallerIdentityResponse struct {
		GetCallerIdentityResult struct {
			Account string
			Arn     string
		}
	}
}

func executeSTSIdentityRequest(req *http.Request) (*stsIdentityResponse, error) {
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer func() {
		// always read the body to EOF and close
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, trace.AccessDenied("aws sts api returned status: %q", resp.Status)
	}

	var identityResponse stsIdentityResponse
	decoder := json.NewDecoder(resp.Body)
	if err := decoder.Decode(&identityResponse); err != nil {
		return nil, trace.Wrap(err)
	}
	return &identityResponse, nil
}

func checkIAMAllowRules(identityResponse *stsIdentityResponse, provisionToken types.ProvisionToken) error {
	return trace.NotImplemented("checkIAMAllowRules")
}

func (a *Server) CheckIAMRequest(ctx context.Context, challenge string, req types.RegisterUsingTokenRequest) error {
	tokenName := req.Token
	provisionToken, err := a.GetCache().GetToken(ctx, tokenName)
	if err != nil {
		return trace.Wrap(err)
	}

	identityRequest, err := parseSTSRequest(req.STSIdentityRequest)
	if err != nil {
		return trace.Wrap(err)
	}

	if err := validateSTSIdentityRequest(identityRequest, challenge); err != nil {
		return trace.Wrap(err)
	}

	identityResponse, err := executeSTSIdentityRequest(identityRequest)
	if err != nil {
		return trace.Wrap(err)
	}

	if err := checkIAMAllowRules(identityResponse, provisionToken); err != nil {
		return trace.Wrap(err)
	}

	return nil
}
