package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLocalSecretFindingsDetectsPrivateKey(t *testing.T) {
	findings := localSecretFindings("private.key", "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----")

	if !containsFinding(findings, "PEM private key") {
		t.Fatalf("expected private key finding, got %#v", findings)
	}
}

func TestLocalSecretFindingsDetectsPrefixedCredentialNames(t *testing.T) {
	content := `
services:
  db:
    environment:
      POSTGRES_PASSWORD: postgres
      DB_PASSWORD: postgres
`

	findings := localSecretFindings("compose.yml", content)

	if !containsFinding(findings, "POSTGRES_PASSWORD") {
		t.Fatalf("expected POSTGRES_PASSWORD finding, got %#v", findings)
	}
	if !containsFinding(findings, "DB_PASSWORD") {
		t.Fatalf("expected DB_PASSWORD finding, got %#v", findings)
	}
}

func TestLocalSecretFindingsIgnoresPlaceholders(t *testing.T) {
	findings := localSecretFindings("config.yml", "API_KEY: your_api_key_here\nTOKEN: placeholder")

	if len(findings) != 0 {
		t.Fatalf("expected no findings for placeholders, got %#v", findings)
	}
}

func TestGetSecretScanLLMOnlyBypassesLocalFindings(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/api/chat" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}

		_ = json.NewEncoder(w).Encode(AIResponse{
			Message: struct {
				Content string `json:"content"`
			}{
				Content: "VERDICT: False\nREASONING: model did not find an embedded secret",
			},
		})
	}))
	defer server.Close()

	verdict, reasoning := getSecretScan(
		server.Client(),
		server.URL,
		"test-model",
		"private.key",
		"-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----",
		scanModeLLMOnly,
	)

	if verdict != "False" {
		t.Fatalf("expected LLM verdict to be used, got %q with reasoning %q", verdict, reasoning)
	}
	if !strings.Contains(reasoning, "LLM (test-model)") {
		t.Fatalf("expected LLM reasoning, got %q", reasoning)
	}
	if calls != 1 {
		t.Fatalf("expected one LLM call, got %d", calls)
	}
}

func TestGetSecretScanCombinedModeCallsLLMWithLocalFindings(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/api/chat" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}

		_ = json.NewEncoder(w).Encode(AIResponse{
			Message: struct {
				Content string `json:"content"`
			}{
				Content: "VERDICT: True\nREASONING: model confirmed embedded private key material",
			},
		})
	}))
	defer server.Close()

	verdict, reasoning := getSecretScan(
		server.Client(),
		server.URL,
		"test-model",
		"private.key",
		"-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----",
		scanModeCombined,
	)

	if verdict != "True" {
		t.Fatalf("expected true verdict, got %q with reasoning %q", verdict, reasoning)
	}
	if !strings.Contains(reasoning, "Local detector:") {
		t.Fatalf("expected local reasoning, got %q", reasoning)
	}
	if !strings.Contains(reasoning, "LLM (test-model)") {
		t.Fatalf("expected LLM reasoning, got %q", reasoning)
	}
	if calls != 1 {
		t.Fatalf("expected one LLM call, got %d", calls)
	}
}

func TestGetLocalSecretScanUsesOnlyLocalFindings(t *testing.T) {
	verdict, reasoning := getLocalSecretScan(
		"private.key",
		"-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----",
	)

	if verdict != "True" {
		t.Fatalf("expected local detector verdict, got %q with reasoning %q", verdict, reasoning)
	}
	if !strings.Contains(reasoning, "Local detector:") {
		t.Fatalf("expected local detector reasoning, got %q", reasoning)
	}
}

func TestGetLocalSecretScanReturnsFalseWithoutLocalFindings(t *testing.T) {
	verdict, reasoning := getLocalSecretScan("main.go", "package main\n")

	if verdict != "False" {
		t.Fatalf("expected false verdict, got %q with reasoning %q", verdict, reasoning)
	}
	if !strings.Contains(reasoning, "no hardcoded secret found") {
		t.Fatalf("expected no-finding reasoning, got %q", reasoning)
	}
}

func containsFinding(findings []string, needle string) bool {
	for _, finding := range findings {
		if strings.Contains(finding, needle) {
			return true
		}
	}
	return false
}
