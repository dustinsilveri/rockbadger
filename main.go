package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	defaultOllamaBaseURL = "http://127.0.0.1:11434"
	defaultModelName     = "qwen2.5-coder:1.5b"
)

var (
	awsAccessKeyPattern = regexp.MustCompile(`\b(AKIA|ASIA)[A-Z0-9]{16}\b`)
	credentialPattern   = regexp.MustCompile(`(?i)\b([a-z0-9_-]*(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret|private[_-]?key)[a-z0-9_-]*)\b\s*[:=]\s*['"]?([^'"\s,#]+)`)
)

type AIResponse struct {
	Message struct {
		Content string `json:"content"`
	} `json:"message"`
	Error string `json:"error"`
}

type SecretFinding struct {
	FilePath  string
	Reasoning string
}

type scanMode int

const (
	scanModeCombined scanMode = iota
	scanModeLLMOnly
	scanModeNoLLM
)

func ollamaBaseURL() string {
	if value := os.Getenv("OLLAMA_URL"); value != "" {
		return strings.TrimRight(value, "/")
	}
	return defaultOllamaBaseURL
}

func modelName() string {
	if value := os.Getenv("OLLAMA_MODEL"); value != "" {
		return value
	}
	return defaultModelName
}

func ensureOllamaModel(client *http.Client, baseURL, model string) error {
	fmt.Printf("📡 Checking Ollama model %q...\n", model)

	req, err := http.NewRequest(http.MethodGet, baseURL+"/api/tags", nil)
	if err != nil {
		return err
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("could not connect to Ollama at %s: %w", baseURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("Ollama model list failed with HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var tags struct {
		Models []struct {
			Name string `json:"name"`
		} `json:"models"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tags); err != nil {
		return fmt.Errorf("could not decode Ollama model list: %w", err)
	}

	for _, candidate := range tags.Models {
		if candidate.Name == model {
			return nil
		}
	}

	fmt.Printf("📥 Pulling Ollama model %q...\n", model)
	payload := map[string]any{
		"name":   model,
		"stream": false,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	resp, err = client.Post(baseURL+"/api/pull", "application/json", bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("could not pull Ollama model %q: %w", model, err)
	}
	defer resp.Body.Close()

	responseBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("could not pull Ollama model %q, HTTP %d: %s", model, resp.StatusCode, strings.TrimSpace(string(responseBody)))
	}

	var pullResp struct {
		Status string `json:"status"`
		Error  string `json:"error"`
	}
	if err := json.Unmarshal(responseBody, &pullResp); err == nil && pullResp.Error != "" {
		return errors.New(pullResp.Error)
	}

	return nil
}

func localSecretFindings(filePath, code string) []string {
	var findings []string
	lowerPath := strings.ToLower(filePath)
	lowerCode := strings.ToLower(code)

	if strings.Contains(code, "-----BEGIN ") && strings.Contains(code, "PRIVATE KEY-----") {
		findings = append(findings, "contains a PEM private key block")
	}

	if awsAccessKeyPattern.MatchString(code) {
		findings = append(findings, "contains an AWS access key identifier")
	}

	for _, match := range credentialPattern.FindAllStringSubmatch(code, -1) {
		if len(match) < 3 || !looksLikeSecretValue(match[2]) {
			continue
		}
		findings = append(findings, fmt.Sprintf("assigns a concrete value to %q", match[1]))
	}

	if strings.HasSuffix(lowerPath, ".key") && strings.Contains(lowerCode, "private key") {
		findings = append(findings, "private key material is stored in a .key file")
	}

	if strings.Contains(lowerCode, "insert into") && strings.Contains(lowerCode, "password") {
		findings = append(findings, "SQL seed data includes password values")
	}

	return dedupe(findings)
}

func looksLikeSecretValue(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) < 4 {
		return false
	}

	normalized := strings.ToLower(strings.Trim(value, `"'`))
	if normalized == "" ||
		strings.HasPrefix(normalized, "$") ||
		strings.HasPrefix(normalized, "os.getenv") ||
		strings.HasPrefix(normalized, "getenv") ||
		strings.Contains(normalized, "example") ||
		strings.Contains(normalized, "changeme") ||
		strings.Contains(normalized, "placeholder") ||
		strings.Contains(normalized, "your_") {
		return false
	}

	return true
}

func dedupe(values []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0, len(values))
	for _, value := range values {
		if seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	return result
}

func getAISecretScan(client *http.Client, baseURL, model, filePath, code string) (string, string) {
	// Refined prompt specifically for finding secrets without Semgrep
	prompt := fmt.Sprintf(`Analyze the following file content for hardcoded secret VALUES.

Return True only when the file contains an actual embedded credential value, such as:
- API keys, access tokens, passwords, private keys, or seed credentials
- database passwords or service credentials written directly in config

Return False for:
- environment variable names like DB_PASSWORD without the value
- code that reads secrets from os.Getenv or a similar API
- format placeholders like password=%%s, ${PASSWORD}, or $DB_PASSWORD
- variable, field, or column names named password, token, key, or secret without a literal secret value
- SQL injection issues without a hardcoded secret value
- commands that generate keys but do not contain a generated private key value
- public certificates
- dependency files without embedded credentials

Important: a database DSN template such as "password=%%s" combined with os.Getenv("DB_PASSWORD") is not a hardcoded secret.

File: %s
Content:
%s

Respond exactly as:
VERDICT: True or False
REASONING: one short explanation`, filePath, code)

	payload := map[string]any{
		"model": model,
		"messages": []map[string]string{
			{"role": "system", "content": "You are a precise secret detector. Do not report vulnerabilities or secret variable names unless an actual credential value is embedded in the file."},
			{"role": "user", "content": prompt},
		},
		"stream": false,
		"options": map[string]any{
			"temperature": 0.0,
		},
	}

	body, _ := json.Marshal(payload)
	resp, err := client.Post(baseURL+"/api/chat", "application/json", bytes.NewBuffer(body))
	if err != nil {
		return "Unknown", fmt.Sprintf("Could not connect to Ollama: %v", err)
	}
	defer resp.Body.Close()

	responseBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "Unknown", fmt.Sprintf("Ollama returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(responseBody)))
	}

	var aiResp AIResponse
	if err := json.Unmarshal(responseBody, &aiResp); err != nil {
		return "Unknown", fmt.Sprintf("Could not decode Ollama response: %v", err)
	}

	if aiResp.Error != "" {
		return "Unknown", aiResp.Error
	}

	if aiResp.Message.Content == "" {
		return "Unknown", "AI returned no response"
	}

	fullText := aiResp.Message.Content
	parts := strings.SplitN(fullText, "REASONING:", 2)
	verdict := strings.Replace(parts[0], "VERDICT:", "", 1)
	reasoning := ""
	if len(parts) > 1 {
		reasoning = parts[1]
	}

	verdict = strings.TrimSpace(verdict)
	reasoning = strings.TrimSpace(reasoning)
	if strings.Contains(strings.ToLower(verdict), "true") {
		return "True", "LLM (" + model + "): " + reasoning
	}
	if strings.Contains(strings.ToLower(verdict), "false") {
		return "False", "LLM (" + model + "): " + reasoning
	}

	return verdict, "LLM (" + model + "): " + reasoning
}

func getSecretScan(client *http.Client, baseURL, model, filePath, code string, mode scanMode) (string, string) {
	switch mode {
	case scanModeLLMOnly:
		return getAISecretScan(client, baseURL, model, filePath, code)
	case scanModeNoLLM:
		return getLocalSecretScan(filePath, code)
	default:
		localFindings := localSecretFindings(filePath, code)
		aiVerdict, aiReasoning := getAISecretScan(client, baseURL, model, filePath, code)

		if len(localFindings) == 0 {
			return aiVerdict, aiReasoning
		}

		localReasoning := "Local detector: " + strings.Join(localFindings, "; ")
		if strings.Contains(strings.ToLower(aiVerdict), "true") {
			return "True", localReasoning + " | " + aiReasoning
		}
		if strings.Contains(strings.ToLower(aiVerdict), "false") {
			return "True", localReasoning + " | " + aiReasoning
		}
		return "True", localReasoning + " | LLM inconclusive: " + aiReasoning
	}
}

func getLocalSecretScan(filePath, code string) (string, string) {
	if findings := localSecretFindings(filePath, code); len(findings) > 0 {
		return "True", "Local detector: " + strings.Join(findings, "; ")
	}

	return "False", "Local detector: no hardcoded secret found"
}

func displayFindings(findings []SecretFinding) {
	fmt.Println("\n🚨 --- CONFIRMED SECRETS FOUND --- 🚨")
	if len(findings) == 0 {
		fmt.Println("No secrets identified in this scan.")
		return
	}

	for _, finding := range findings {
		fmt.Printf("📍 File: %s\n 💡 Reason: %s\n\n", finding.FilePath, finding.Reasoning)
	}
}

func main() {
	startTime := time.Now()
	llmOnly := flag.Bool("llm-only", false, "only use the LLM to identify secrets; bypass local detectors")
	noLLM := flag.Bool("no-llm", false, "do not use the LLM; only use local detectors")
	flag.Parse()

	if *llmOnly && *noLLM {
		fmt.Println("❌ Choose either --llm-only or --no-llm, not both.")
		return
	}

	mode := scanModeCombined
	if *llmOnly {
		mode = scanModeLLMOnly
	}
	if *noLLM {
		mode = scanModeNoLLM
	}

	var client http.Client
	var baseURL, model string
	if mode != scanModeNoLLM {
		client = http.Client{Timeout: 10 * time.Minute}
		baseURL = ollamaBaseURL()
		model = modelName()
		if err := ensureOllamaModel(&client, baseURL, model); err != nil {
			fmt.Printf("❌ Ollama Setup Error: %v\n", err)
			fmt.Printf("Set OLLAMA_URL or OLLAMA_MODEL if your local setup differs. Current model: %s\n", model)
			return
		}
	}

	scanPath, _ := os.Getwd()
	if flag.NArg() > 0 {
		scanPath, _ = filepath.Abs(flag.Arg(0))
	}

	fmt.Printf("🔍 Scanning Directory for Secrets: %s\n", scanPath)
	if *llmOnly {
		fmt.Println("🤖 LLM-only mode enabled; local detectors are disabled.")
	}
	if *noLLM {
		fmt.Println("🔎 No-LLM mode enabled; only local detectors will run.")
	}
	if mode == scanModeCombined {
		fmt.Println("🔎 Combined mode enabled; local detectors and the LLM will both run.")
	}

	processed := 0
	findings := []SecretFinding{}

	err := filepath.Walk(scanPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories and common non-text folders
		if info.IsDir() || strings.Contains(path, ".git") || strings.Contains(path, "node_modules") {
			return nil
		}

		// Limit file size to avoid overloading LLM (e.g., 500KB)
		if info.Size() > 500000 {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		fmt.Printf("🔎 Analyzing %s...\n", filepath.Base(path))
		verdict, reasoning := getSecretScan(&client, baseURL, model, path, string(content), mode)

		processed++
		if strings.Contains(strings.ToLower(verdict), "true") {
			findings = append(findings, SecretFinding{
				FilePath:  path,
				Reasoning: reasoning,
			})
		}

		return nil
	})

	if err != nil {
		fmt.Printf("❌ Walk error: %v\n", err)
	}

	duration := time.Since(startTime).Round(time.Second)

	fmt.Println("--------------------------------------------------")
	fmt.Printf("🎉 Finished in: %s\n", duration)
	fmt.Printf("📊 Summary: %d processed | %d confirmed secrets\n", processed, len(findings))
	fmt.Println("--------------------------------------------------")

	displayFindings(findings)
}
