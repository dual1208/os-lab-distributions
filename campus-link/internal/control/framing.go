package control

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
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
	if err := validateCanonicalJSONObject(line, reflect.TypeOf(dst)); err != nil {
		return fmt.Errorf("decode control message: %w", err)
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

func validateCanonicalJSONObject(data []byte, valueType reflect.Type) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return errors.New("control message must be a JSON object")
	}
	if err := rejectEscapedObjectKeys(data); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := validateCanonicalJSONValue(dec, valueType); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values in one control message")
		}
		return err
	}
	return nil
}

func validateCanonicalJSONValue(dec *json.Decoder, valueType reflect.Type) error {
	for valueType != nil && valueType.Kind() == reflect.Pointer {
		valueType = valueType.Elem()
	}
	token, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		fields := exactJSONFields(valueType)
		for dec.More() {
			keyToken, err := dec.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("control object key is not a string")
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("duplicate control object key %q", key)
			}
			seen[key] = struct{}{}
			var childType reflect.Type
			switch {
			case valueType != nil && valueType.Kind() == reflect.Struct:
				var found bool
				childType, found = fields[key]
				if !found {
					return fmt.Errorf("unknown or non-canonical control field %q", key)
				}
			case valueType != nil && valueType.Kind() == reflect.Map:
				if valueType.Key().Kind() != reflect.String {
					return errors.New("control map key must be a string")
				}
				childType = valueType.Elem()
			}
			if err := validateCanonicalJSONValue(dec, childType); err != nil {
				return err
			}
		}
		end, err := dec.Token()
		if err != nil {
			return err
		}
		if end != json.Delim('}') {
			return errors.New("unterminated control object")
		}
	case '[':
		var childType reflect.Type
		if valueType != nil && (valueType.Kind() == reflect.Array || valueType.Kind() == reflect.Slice) {
			childType = valueType.Elem()
		}
		for dec.More() {
			if err := validateCanonicalJSONValue(dec, childType); err != nil {
				return err
			}
		}
		end, err := dec.Token()
		if err != nil {
			return err
		}
		if end != json.Delim(']') {
			return errors.New("unterminated control array")
		}
	default:
		return fmt.Errorf("unexpected control delimiter %q", delim)
	}
	return nil
}

func exactJSONFields(valueType reflect.Type) map[string]reflect.Type {
	fields := make(map[string]reflect.Type)
	if valueType == nil || valueType.Kind() != reflect.Struct {
		return fields
	}
	for index := 0; index < valueType.NumField(); index++ {
		field := valueType.Field(index)
		if field.PkgPath != "" {
			continue
		}
		name := field.Name
		if tag := field.Tag.Get("json"); tag != "" {
			name = strings.Split(tag, ",")[0]
		}
		if name == "-" {
			continue
		}
		if name == "" {
			name = field.Name
		}
		fields[name] = field.Type
	}
	return fields
}

func rejectEscapedObjectKeys(data []byte) error {
	type container struct {
		kind      byte
		expectKey bool
	}
	stack := make([]container, 0, 4)
	inString, escaped, keyString := false, false, false
	for _, b := range data {
		if inString {
			if escaped {
				escaped = false
				continue
			}
			if b == '\\' {
				if keyString {
					return errors.New("escaped control object keys are not canonical")
				}
				escaped = true
				continue
			}
			if b == '"' {
				inString = false
				if keyString && len(stack) != 0 {
					stack[len(stack)-1].expectKey = false
				}
			}
			continue
		}
		switch b {
		case '{':
			stack = append(stack, container{kind: '{', expectKey: true})
		case '[':
			stack = append(stack, container{kind: '['})
		case '}', ']':
			if len(stack) != 0 {
				stack = stack[:len(stack)-1]
			}
		case ',':
			if len(stack) != 0 && stack[len(stack)-1].kind == '{' {
				stack[len(stack)-1].expectKey = true
			}
		case '"':
			inString = true
			keyString = len(stack) != 0 && stack[len(stack)-1].kind == '{' && stack[len(stack)-1].expectKey
		}
	}
	return nil
}
