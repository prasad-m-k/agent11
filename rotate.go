package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"sync"
)

// rotatingFile is an io.Writer that appends to a log file and rotates it once
// the next write would push it past maxBytes or maxLines, whichever comes
// first. Old files are kept as path.1 (newest) through path.N (oldest).
// A limit of 0 disables that check.
type rotatingFile struct {
	mu         sync.Mutex
	path       string
	maxBytes   int64
	maxLines   int64
	maxBackups int

	f     *os.File
	size  int64
	lines int64
}

func openRotatingFile(path string, maxBytes, maxLines int64, maxBackups int) (*rotatingFile, error) {
	r := &rotatingFile{path: path, maxBytes: maxBytes, maxLines: maxLines, maxBackups: maxBackups}
	if err := r.open(); err != nil {
		return nil, err
	}
	return r, nil
}

// open opens (or creates) the active log file and picks up its current size
// and line count, so limits hold across restarts.
func (r *rotatingFile) open() error {
	// 0600: the clipboard can hold passwords and tokens.
	f, err := os.OpenFile(r.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	size, lines, err := countFile(r.path)
	if err != nil {
		f.Close()
		return err
	}
	r.f, r.size, r.lines = f, size, lines
	return nil
}

func countFile(path string) (size, lines int64, err error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()
	buf := make([]byte, 64*1024)
	for {
		n, err := f.Read(buf)
		size += int64(n)
		lines += int64(bytes.Count(buf[:n], []byte{'\n'}))
		if err == io.EOF {
			return size, lines, nil
		}
		if err != nil {
			return 0, 0, err
		}
	}
}

func (r *rotatingFile) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	newLines := int64(bytes.Count(p, []byte{'\n'}))
	overSize := r.maxBytes > 0 && r.size+int64(len(p)) > r.maxBytes
	overLines := r.maxLines > 0 && r.lines+newLines > r.maxLines
	// Never rotate an empty file: an entry larger than the limit gets a file
	// of its own instead of rotating forever.
	if r.size > 0 && (overSize || overLines) {
		if err := r.rotate(); err != nil {
			return 0, fmt.Errorf("rotate %s: %w", r.path, err)
		}
	}

	n, err := r.f.Write(p)
	r.size += int64(n)
	r.lines += int64(bytes.Count(p[:n], []byte{'\n'}))
	return n, err
}

func (r *rotatingFile) rotate() error {
	if err := r.f.Close(); err != nil {
		return err
	}
	if r.maxBackups <= 0 {
		if err := os.Remove(r.path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		return r.open()
	}
	oldest := fmt.Sprintf("%s.%d", r.path, r.maxBackups)
	if err := os.Remove(oldest); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	for i := r.maxBackups - 1; i >= 1; i-- {
		from, to := fmt.Sprintf("%s.%d", r.path, i), fmt.Sprintf("%s.%d", r.path, i+1)
		if err := os.Rename(from, to); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	if err := os.Rename(r.path, r.path+".1"); err != nil {
		return err
	}
	return r.open()
}

func (r *rotatingFile) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.f.Close()
}
