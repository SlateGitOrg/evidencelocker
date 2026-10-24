package persistence

import (
	"bytes"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// ErrBinaryPlist is returned for "bplist00" files, which this parser does
// not decode (they are still hashed and captured).
var ErrBinaryPlist = errors.New("binary property list not supported")

// maxPlistDepth bounds nesting so hostile files cannot exhaust the stack.
const maxPlistDepth = 64

// ParsePlist decodes an XML property list into Go values:
// map[string]any, []any, string, bool, int64, float64, []byte (data) and
// string (date, kept verbatim).
func ParsePlist(b []byte) (any, error) {
	if bytes.HasPrefix(b, []byte("bplist")) {
		return nil, ErrBinaryPlist
	}
	d := xml.NewDecoder(bytes.NewReader(b))
	d.Strict = true
	for {
		tok, err := d.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil, errors.New("plist: no <plist> element")
			}
			return nil, fmt.Errorf("plist: %w", err)
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		if se.Name.Local != "plist" {
			return nil, fmt.Errorf("plist: root element <%s>", se.Name.Local)
		}
		v, end, err := plistValue(d, 0)
		if err != nil {
			return nil, err
		}
		if end {
			return nil, errors.New("plist: empty <plist>")
		}
		return v, nil
	}
}

// plistValue reads the next value element. end reports that the enclosing
// element closed instead (used to terminate <array> and <dict>).
func plistValue(d *xml.Decoder, depth int) (v any, end bool, err error) {
	if depth > maxPlistDepth {
		return nil, false, errors.New("plist: nesting too deep")
	}
	for {
		tok, err := d.Token()
		if err != nil {
			return nil, false, fmt.Errorf("plist: %w", err)
		}
		switch t := tok.(type) {
		case xml.EndElement:
			return nil, true, nil
		case xml.StartElement:
			v, err := plistElement(d, t, depth)
			return v, false, err
		}
	}
}

func plistElement(d *xml.Decoder, se xml.StartElement, depth int) (any, error) {
	switch se.Name.Local {
	case "dict":
		m := map[string]any{}
		for {
			tok, err := d.Token()
			if err != nil {
				return nil, fmt.Errorf("plist dict: %w", err)
			}
			switch t := tok.(type) {
			case xml.EndElement:
				return m, nil
			case xml.StartElement:
				if t.Name.Local != "key" {
					return nil, fmt.Errorf("plist dict: expected <key>, got <%s>", t.Name.Local)
				}
				k, err := text(d)
				if err != nil {
					return nil, err
				}
				v, end, err := plistValue(d, depth+1)
				if err != nil {
					return nil, err
				}
				if end {
					return nil, fmt.Errorf("plist dict: key %q has no value", k)
				}
				m[k] = v
			}
		}
	case "array":
		a := []any{}
		for {
			v, end, err := plistValue(d, depth+1)
			if err != nil {
				return nil, err
			}
			if end {
				return a, nil
			}
			a = append(a, v)
		}
	case "true", "false":
		if err := d.Skip(); err != nil {
			return nil, fmt.Errorf("plist: %w", err)
		}
		return se.Name.Local == "true", nil
	case "string", "date":
		return text(d)
	case "integer":
		s, err := text(d)
		if err != nil {
			return nil, err
		}
		n, err := strconv.ParseInt(strings.TrimSpace(s), 0, 64)
		if err != nil {
			return nil, fmt.Errorf("plist integer %q: %w", s, err)
		}
		return n, nil
	case "real":
		s, err := text(d)
		if err != nil {
			return nil, err
		}
		f, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
		if err != nil {
			return nil, fmt.Errorf("plist real %q: %w", s, err)
		}
		return f, nil
	case "data":
		s, err := text(d)
		if err != nil {
			return nil, err
		}
		clean := strings.Join(strings.Fields(s), "")
		b, err := base64.StdEncoding.DecodeString(clean)
		if err != nil {
			return nil, fmt.Errorf("plist data: %w", err)
		}
		return b, nil
	default:
		return nil, fmt.Errorf("plist: unknown element <%s>", se.Name.Local)
	}
}

// text reads character data up to the current element's end tag.
func text(d *xml.Decoder) (string, error) {
	var sb strings.Builder
	for {
		tok, err := d.Token()
		if err != nil {
			return "", fmt.Errorf("plist: %w", err)
		}
		switch t := tok.(type) {
		case xml.CharData:
			sb.Write(t)
		case xml.EndElement:
			return sb.String(), nil
		case xml.StartElement:
			return "", fmt.Errorf("plist: unexpected <%s> in text element", t.Name.Local)
		}
	}
}
