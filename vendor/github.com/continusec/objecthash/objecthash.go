package objecthash

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"golang.org/x/text/unicode/norm"
)

var (
	ErrNormalizingFloat       = errors.New("ErrNormalizingFloat")
	ErrUnrecognizedObjectType = errors.New("ErrUnrecognizedObjectType")
	ErrNotImplementedYet      = errors.New("ErrNotImplementedYet")
)

const (
	REDACTED_PREFIX = "***REDACTED*** Hash: "
)

func hash(t byte, b []byte) []byte {
	h := sha256.New()
	h.Write([]byte{t})
	h.Write(b)
	return h.Sum(nil)
}

// FIXME: if What You Hash Is What You Get, then this needs to be safe
// to use as a set.
// Note: not actually safe to use as a set
type Set []interface{}

type sortableHashes [][]byte

func (h sortableHashes) Len() int           { return len(h) }
func (h sortableHashes) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h sortableHashes) Less(i, j int) bool { return bytes.Compare(h[i], h[j]) < 0 }

func hashSet(s Set, redPref string) ([]byte, error) {
	h := make([][]byte, len(s))
	for n, e := range s {
		var err error
		if h[n], err = ObjectHashWithRedaction(e, redPref); err != nil {
			return nil, err
		}
	}
	sort.Sort(sortableHashes(h))
	b := new(bytes.Buffer)
	var prev []byte
	for _, hh := range h {
		if !bytes.Equal(hh, prev) {
			b.Write(hh)
		}
		prev = hh
	}
	return hash('s', b.Bytes()), nil
}

func hashList(l []interface{}, redPref string) ([]byte, error) {
	h := new(bytes.Buffer)
	for _, o := range l {
		var b []byte
		var err error
		if b, err = ObjectHashWithRedaction(o, redPref); err != nil {
			return nil, err
		}
		h.Write(b)
	}
	return hash('l', h.Bytes()), nil
}

func hashUnicode(s string) ([]byte, error) {
	return hash('u', norm.NFC.Bytes([]byte(s))), nil
}

type hashEntry struct {
	khash []byte
	vhash []byte
}
type byKHash []hashEntry

func (h byKHash) Len() int      { return len(h) }
func (h byKHash) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h byKHash) Less(i, j int) bool {
	return bytes.Compare(h[i].khash, h[j].khash) < 0
}

func hashDict(d map[string]interface{}, redPref string) ([]byte, error) {
	e := make([]hashEntry, len(d))
	n := 0
	for k, v := range d {
		var err error
		if e[n].khash, err = ObjectHashWithRedaction(k, redPref); err != nil {
			return nil, err
		}
		if e[n].vhash, err = ObjectHashWithRedaction(v, redPref); err != nil {
			return nil, err
		}
		n++
	}
	sort.Sort(byKHash(e))
	h := new(bytes.Buffer)
	for _, ee := range e {
		h.Write(ee.khash)
		h.Write(ee.vhash)
	}
	return hash('d', h.Bytes()), nil
}

func floatNormalize(f float64) (string, error) {
	// special case 0
	if f == 0.0 {
		return `+0:`, nil
	}

	// sign
	s := `+`
	if f < 0 {
		s = `-`
		f = -f
	}
	// exponent
	e := 0
	for f > 1 {
		f /= 2
		e++
	}
	for f <= .5 {
		f *= 2
		e--
	}
	s += fmt.Sprintf("%d:", e)
	// mantissa
	if f > 1 || f <= .5 {
		return "", ErrNormalizingFloat
	}
	for f != 0 {
		if f >= 1 {
			s += `1`
			f -= 1
		} else {
			s += `0`
		}
		if f >= 1 {
			return "", ErrNormalizingFloat
		}
		if len(s) >= 1000 {
			return "", ErrNormalizingFloat
		}
		f *= 2
	}
	return s, nil
}

func hashFloat(f float64) ([]byte, error) {
	var n string
	var err error
	if n, err = floatNormalize(f); err != nil {
		return nil, err
	}
	return hash('f', []byte(n)), nil
}

func hashInt(i int) ([]byte, error) {
	return hash('i', []byte(fmt.Sprintf("%d", i))), nil
}

func hashBool(b bool) ([]byte, error) {
	var bb []byte
	if b {
		bb = []byte{'1'}
	} else {
		bb = []byte{'0'}
	}
	return hash('b', bb), nil
}

func ObjectHash(o interface{}) ([]byte, error) {
	return ObjectHashWithRedaction(o, "")
}

func ObjectHashWithStdRedaction(o interface{}) ([]byte, error) {
	return ObjectHashWithRedaction(o, REDACTED_PREFIX)
}

func ObjectHashWithRedaction(o interface{}, redPref string) ([]byte, error) {
	switch v := o.(type) {
	case []interface{}:
		return hashList(v, redPref)
	case string:
		if (len(redPref) > 0) && strings.HasPrefix(v, redPref) {
			return hex.DecodeString(v[len(redPref):])
		} else {
			return hashUnicode(v)
		}
	case map[string]interface{}:
		return hashDict(v, redPref)
	case float64:
		return hashFloat(v)
	case nil:
		return hash('n', nil), nil
	case int:
		return hashInt(v)
	case Set:
		return hashSet(v, redPref)
	case bool:
		return hashBool(v)
	default:
		return nil, ErrUnrecognizedObjectType
	}
}

func CommonJSONHash(j []byte) ([]byte, error) {
	var f interface{}
	if err := json.Unmarshal(j, &f); err != nil {
		return nil, err
	}
	return ObjectHash(f)
}

/*
 * Redact stuff
 */

func Redactable(o interface{}) (interface{}, error) {
	switch v := o.(type) {
	case []interface{}:
		return redactableList(v)
	case map[string]interface{}:
		return redactableDict(v)
	default:
		return o, nil
	}
}

func nonce() (string, error) {
	n := make([]byte, 32)
	_, err := rand.Read(n)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(n), nil
}

func redactableIt(p interface{}) (interface{}, error) {
	n, err := nonce()
	if err != nil {
		return nil, err
	}
	return []interface{}{n, p}, nil
}

func redactableList(p []interface{}) (interface{}, error) {
	rv := make([]interface{}, len(p))
	for i, a := range p {
		var err error
		rv[i], err = Redactable(a)
		if err != nil {
			return nil, err
		}
	}
	return rv, nil
}

func redactableDict(p map[string]interface{}) (interface{}, error) {
	rv := make(map[string]interface{})
	for k, v := range p {
		c, err := Redactable(v)
		if err != nil {
			return nil, err
		}
		rv[k], err = redactableIt(c)
		if err != nil {
			return nil, err
		}
	}
	return rv, nil
}

/*
 * Unredact stuff
 */
func UnredactableWithStdPrefix(o interface{}) (interface{}, error) {
	return Unredactable(o, REDACTED_PREFIX)
}

func Unredactable(o interface{}, redPref string) (interface{}, error) {
	switch v := o.(type) {
	case []interface{}:
		return unredactableList(v, redPref)
	case map[string]interface{}:
		return unredactableDict(v, redPref)
	default:
		return o, nil
	}
}

func unredactableIt(o interface{}, redPref string) (bool, interface{}, error) {
	switch v := o.(type) {
	case []interface{}:
		if len(v) != 2 {
			return false, nil, ErrUnrecognizedObjectType
		}
		rv, err := Unredactable(v[1], redPref)
		if err != nil {
			return false, nil, err
		}
		return true, rv, nil
	case string:
		if !strings.HasPrefix(v, redPref) {
			return false, nil, ErrUnrecognizedObjectType
		}
		return false, nil, nil
	default:
		return false, nil, ErrUnrecognizedObjectType
	}
}

func unredactableList(p []interface{}, redPref string) (interface{}, error) {
	rv := make([]interface{}, len(p))
	for i, a := range p {
		var err error
		rv[i], err = Unredactable(a, redPref)
		if err != nil {
			return nil, err
		}
	}
	return rv, nil
}

func unredactableDict(p map[string]interface{}, redPref string) (interface{}, error) {
	rv := make(map[string]interface{})
	for k, v := range p {
		ok, v, err := unredactableIt(v, redPref)
		if err != nil {
			return nil, err
		}
		if ok {
			rv[k] = v
		}
	}
	return rv, nil
}

type Filterer map[string]Filterer

func CreateFilterer(allowed string) *Filterer {
	m := make(Filterer)
	for _, s := range strings.Split(allowed, ",") {
		n := m
		for _, j := range strings.Split(s, "/") {
			j = strings.TrimSpace(j)
			o, ok := n[j]
			if !ok {
				o = make(Filterer)
				n[j] = o
			}
			n = o
		}
	}
	return &m
}

func (self *Filterer) IsAllowed(path []string) bool {
	n := self
	for _, j := range path {
		_, ok := (*n)["*"]
		if ok {
			return true
		} else {
			o, ok := (*n)[j]
			if ok {
				n = &o
			} else {
				return false
			}
		}
	}
	return true
}

/* Filter a previously redacted object. */
// Format of allowed is:  expr(,expr)*
// Format of expr is:	 ident(/ident)*
// Format if ident is:	either * or not a comma or /
func Filtered(o interface{}, allowed string) (interface{}, error) {
	return filterObj(o, nil, CreateFilterer(allowed))
}

func filterObj(o interface{}, path []string, f *Filterer) (interface{}, error) {
	switch v := o.(type) {
	case []interface{}:
		return filterList(v, path, f)
	case map[string]interface{}:
		return filterDict(v, path, f)
	default:
		return o, nil
	}
}

func filterList(p []interface{}, path []string, f *Filterer) (interface{}, error) {
	rv := make([]interface{}, len(p))
	for i, a := range p {
		var err error
		rv[i], err = filterObj(a, path, f)
		if err != nil {
			return nil, err
		}
	}
	return rv, nil
}

func filterDict(p map[string]interface{}, path []string, f *Filterer) (interface{}, error) {
	rv := make(map[string]interface{})
	for k, v := range p {
		newPath := append(path, k)
		if f.IsAllowed(newPath) {
			var err error
			v, err = filterObj(v, newPath, f)
			if err != nil {
				return nil, err
			}
		} else {
			h, err := ObjectHash(v)
			if err != nil {
				return nil, err
			}
			v = REDACTED_PREFIX + hex.EncodeToString(h)
		}
		rv[k] = v
	}
	return rv, nil
}
