package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestJevClassifier(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") != "Bearer test-key" {
			t.Errorf("auth header = %q", r.Header.Get("Authorization"))
		}
		var req jevRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
		}
		q, ok := req.Questions[jevQuestionKey]
		if req.Model != "typesafe/jev-1.13" || !ok || q.Type != "noul" || !strings.Contains(q.Instructions, "Proprietary source code") {
			t.Errorf("request = %+v", req)
		}
		p := 0.1
		if strings.Contains(req.State, "HIGH") {
			p = 0.97
		}
		json.NewEncoder(w).Encode(map[string]any{"answers": map[string]any{jevQuestionKey: map[string]any{"type": "noul", "noul": p}}})
	}))
	defer srv.Close()

	j := newJevClassifier(jevDefaultModel, "test-key")
	j.url = srv.URL
	c := mustPolicy(t, testPolicyJSON).Classes[0]

	// Long input is chunked and the highest chunk wins.
	long := strings.Repeat("line\n", jevChunkChars/5) + "HIGH\n"
	got, err := j.Classify(context.Background(), ClassifierInput{Features: long}, []*Class{c})
	if err != nil {
		t.Fatal(err)
	}
	if got["code"] != 0.97 {
		t.Errorf("prob = %v, want the max across chunks", got["code"])
	}
	if calls.Load() != 2 {
		t.Errorf("calls = %d, want one per chunk", calls.Load())
	}
}

func TestJevClassifierRetriesOnce(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		http.Error(w, "echo of state would be here", http.StatusInternalServerError)
	}))
	defer srv.Close()
	j := newJevClassifier(jevDefaultModel, "k")
	j.url = srv.URL
	_, err := j.Classify(context.Background(), ClassifierInput{Features: "f"}, []*Class{mustPolicy(t, testPolicyJSON).Classes[0]})
	if err == nil {
		t.Fatal("want an error")
	}
	if strings.Contains(err.Error(), "echo") {
		t.Errorf("error includes the response body: %v", err)
	}
	if calls.Load() != 2 {
		t.Errorf("calls = %d, want 2 (one retry)", calls.Load())
	}
}

func TestChunkText(t *testing.T) {
	s := strings.Repeat("abcdefghi\n", 25)
	chunks := chunkText(s, 64)
	if strings.Join(chunks, "") != s {
		t.Fatal("chunks do not reassemble the input")
	}
	for _, c := range chunks {
		if len(c) > 64 {
			t.Errorf("chunk of %d bytes", len(c))
		}
	}
}
