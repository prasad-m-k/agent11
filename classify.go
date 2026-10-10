package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
)

// Classifier scores text against company classes. The pipeline depends only
// on this interface; vendor details stay in the implementations below.
type Classifier interface {
	Name() string
	// Classify returns, for each class, the probability that the input
	// belongs to it. Classes it could not score are absent from the map.
	Classify(ctx context.Context, in ClassifierInput, classes []*Class) (map[string]float64, error)
}

// ClassifierInput carries what a classifier may see. Features is always set
// and holds no request content. Raw is only filled in for classes that opt in
// with classifier_raw, so a hosted model never sees content by default.
type ClassifierInput struct {
	Features string
	Raw      string
}

// noopClassifier scores nothing. It stands in when no classifier is
// configured, so classes fall back to their deterministic detectors.
type noopClassifier struct{}

func (noopClassifier) Name() string { return "none" }
func (noopClassifier) Classify(context.Context, ClassifierInput, []*Class) (map[string]float64, error) {
	return map[string]float64{}, nil
}

// Jev (TypeSafe's System One model) reached through OpenRouter's System One
// endpoint. Request and response shapes follow the OpenRouter TypeSafe guide:
// a state string plus typed questions in, a "noul" probability per question out.
const (
	jevDefaultURL   = "https://openrouter.ai/api/v1/systemone"
	jevDefaultModel = "typesafe/jev-1.13" // pinned; never "latest" while calibrating
	// jevChunkChars keeps each call well inside Jev's 32K-token context, at a
	// rough 4 characters per token with room for the question.
	jevChunkChars = 90_000
	// jevParallel bounds concurrent calls for one request.
	jevParallel = 8
)

type jevClassifier struct {
	url    string
	model  string
	apiKey string
	client *http.Client
}

func newJevClassifier(model, apiKey string) *jevClassifier {
	return &jevClassifier{url: jevDefaultURL, model: model, apiKey: apiKey, client: &http.Client{}}
}

func (j *jevClassifier) Name() string { return "jev:" + j.model }

type jevQuestion struct {
	Type         string `json:"type"`
	Instructions string `json:"instructions"`
}

type jevRequest struct {
	Model     string                 `json:"model"`
	State     string                 `json:"state"`
	Questions map[string]jevQuestion `json:"questions"`
}

type jevResponse struct {
	Answers map[string]struct {
		Type string   `json:"type"`
		Noul *float64 `json:"noul"`
	} `json:"answers"`
}

// jevQuestionKey is the single question asked per call.
const jevQuestionKey = "belongs"

// Classify sends one typed question per class and chunk, and keeps the
// highest probability across chunks. Class definitions are read from the
// policy at call time, so a policy reload takes effect on the next request.
func (j *jevClassifier) Classify(ctx context.Context, in ClassifierInput, classes []*Class) (map[string]float64, error) {
	type job struct {
		class *Class
		state string
	}
	var jobs []job
	for _, c := range classes {
		state := in.Features
		if c.Classifier.Raw && in.Raw != "" {
			state = in.Raw
		}
		for _, chunk := range chunkText(state, jevChunkChars) {
			jobs = append(jobs, job{c, chunk})
		}
	}

	var (
		mu    sync.Mutex
		probs = map[string]float64{}
		errs  []error
		wg    sync.WaitGroup
		sem   = make(chan struct{}, jevParallel)
	)
	for _, jb := range jobs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				mu.Lock()
				errs = append(errs, ctx.Err())
				mu.Unlock()
				return
			}
			p, err := j.ask(ctx, jb.state, jb.class)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, fmt.Errorf("class %s: %w", jb.class.ID, err))
				return
			}
			probs[jb.class.ID] = max(probs[jb.class.ID], p)
		}()
	}
	wg.Wait()
	if len(errs) > 0 {
		// A partial answer could understate a class, so any failure fails the
		// whole call and the pipeline falls back to its deterministic steps.
		return nil, errors.Join(errs...)
	}
	return probs, nil
}

// ask makes one call, retrying once at most; the caller's context bounds both.
func (j *jevClassifier) ask(ctx context.Context, state string, c *Class) (float64, error) {
	p, err := j.askOnce(ctx, state, c)
	if err != nil && ctx.Err() == nil {
		p, err = j.askOnce(ctx, state, c)
	}
	return p, err
}

func (j *jevClassifier) askOnce(ctx context.Context, state string, c *Class) (float64, error) {
	body, err := json.Marshal(jevRequest{
		Model:     j.model,
		State:     state,
		Questions: map[string]jevQuestion{jevQuestionKey: {Type: "noul", Instructions: classInstructions(c)}},
	})
	if err != nil {
		return 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, j.url, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+j.apiKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := j.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// Status only: an error body could echo the state back.
		io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		return 0, fmt.Errorf("jev: http %d", resp.StatusCode)
	}
	var out jevResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return 0, fmt.Errorf("jev: decode: %w", err)
	}
	a, ok := out.Answers[jevQuestionKey]
	if !ok || a.Noul == nil {
		return 0, errors.New("jev: response has no noul answer")
	}
	if *a.Noul < 0 || *a.Noul > 1 {
		return 0, fmt.Errorf("jev: noul %v out of range", *a.Noul)
	}
	return *a.Noul, nil
}

// classInstructions builds the typed question for a class from its policy
// definition. Examples are kept short so the definition stays near 200 tokens.
func classInstructions(c *Class) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Does this input contain or describe %s?", c.Description)
	if ex := c.Classifier.ExamplesPositive; len(ex) > 0 {
		fmt.Fprintf(&b, " Examples that belong: %s.", strings.Join(ex, "; "))
	}
	if ex := c.Classifier.ExamplesNegative; len(ex) > 0 {
		fmt.Fprintf(&b, " Examples that do not: %s.", strings.Join(ex, "; "))
	}
	return b.String()
}

// chunkText splits s into pieces of at most n bytes, preferring line breaks
// so a chunk rarely cuts a line in half.
func chunkText(s string, n int) []string {
	if len(s) <= n {
		return []string{s}
	}
	var out []string
	for len(s) > n {
		cut := strings.LastIndexByte(s[:n], '\n') + 1
		if cut <= n/2 {
			cut = n
		}
		out = append(out, s[:cut])
		s = s[cut:]
	}
	if s != "" {
		out = append(out, s)
	}
	return out
}
