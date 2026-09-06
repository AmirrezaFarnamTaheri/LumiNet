package boundedio

import (
	"bufio"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestReadLineReturnsBoundedTerminatedLine(t *testing.T) {
	r := bufio.NewReaderSize(strings.NewReader("250 OK\r\nrest"), 4)
	line, err := ReadLine(r, 16)
	if err != nil {
		t.Fatal(err)
	}
	if line != "250 OK\r\n" {
		t.Fatalf("line=%q", line)
	}
}

func TestReadLineRejectsOversizeWithoutUnboundedAccumulation(t *testing.T) {
	r := bufio.NewReaderSize(strings.NewReader(strings.Repeat("x", 128)+"\n"), 8)
	line, err := ReadLine(r, 32)
	if !errors.Is(err, ErrLineTooLong) {
		t.Fatalf("err=%v want ErrLineTooLong", err)
	}
	if len(line) != 0 {
		t.Fatalf("oversize line leaked partial payload of %d bytes", len(line))
	}
}

func TestReadLinePreservesShortEOFContract(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("partial"))
	line, err := ReadLine(r, 16)
	if !errors.Is(err, io.EOF) || line != "partial" {
		t.Fatalf("line=%q err=%v", line, err)
	}
}

func TestReadLineRejectsInvalidLimit(t *testing.T) {
	_, err := ReadLine(bufio.NewReader(strings.NewReader("x\n")), 0)
	if !errors.Is(err, ErrInvalidLineLimit) {
		t.Fatalf("err=%v want ErrInvalidLineLimit", err)
	}
}
