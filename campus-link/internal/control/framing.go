package control

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const MaxMessageSize = 16 * 1024

var ErrMessageTooLarge = errors.New("control message exceeds size limit")

// Decoder reads one newline-delimited JSON control message at a time while
// bounding memory and rejecting fields not understood by this protocol version.
type Decoder struct {
	reader *bufio.Reader
}

func NewDecoder(r io.Reader) *Decoder {
	return &Decoder{reader: bufio.NewReaderSize(r, MaxMessageSize+1)}
}

func (d *Decoder) Decode(dst any) error {
	line, err := d.reader.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) || len(line) > MaxMessageSize {
		return ErrMessageTooLarge
	}
	if err != nil {
		return err
	}
	line = bytes.TrimSpace(line)
	if len(line) == 0 {
		return errors.New("empty control message")
	}
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("decode control message: %w", err)
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("multiple JSON values in one control message")
	}
	return nil
}
