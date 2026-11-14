// Local demo adapter, NOT an isolated/HSM signer. Keys arrive on private stdin.
package main

import (
	"bufio"
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"os"
	"regexp"

	"github.com/cloudflare/circl/blindsign/blindrsa"
)

type request struct {
	Op string `json:"op"`
	KeyID string `json:"key_id"`
	Private string `json:"private_key_pkcs8,omitempty"`
	Blinded string `json:"blinded_msg,omitempty"`
}

type localSigner struct {
	key *rsa.PrivateKey
	id string
}

func decode(value string) ([]byte, error) {
	data, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || base64.RawURLEncoding.EncodeToString(data) != value {
		return nil, errors.New("invalid encoding")
	}
	return data, nil
}

func (s *localSigner) handle(r request) (any, error) {
	if r.Op == "init" && s.key == nil && r.Blinded == "" && regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`).MatchString(r.KeyID) {
		der, err := decode(r.Private)
		if err != nil { return nil, err }
		value, err := x509.ParsePKCS8PrivateKey(der)
		clear(der)
		if err != nil { return nil, err }
		key, ok := value.(*rsa.PrivateKey)
		if !ok || key.N.BitLen() != 3072 || key.E != 65537 { return nil, errors.New("invalid profile") }
		if err = key.Validate(); err != nil { return nil, err }
		public, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
		if err != nil { return nil, err }
		fingerprint := sha256.Sum256(public)
		s.key, s.id = key, r.KeyID
		return map[string]string{"key_id":s.id, "fingerprint":hex.EncodeToString(fingerprint[:])}, nil
	}
	if r.Op != "sign" || s.key == nil || r.KeyID != s.id || r.Private != "" {
		return nil, errors.New("invalid operation")
	}
	original, err := decode(r.Blinded)
	if err != nil || len(original) != 384 { return nil, errors.New("invalid blinded message") }
	representative := new(big.Int).SetBytes(original)
	if representative.Sign() <= 0 || representative.Cmp(s.key.N) >= 0 { return nil, errors.New("invalid representative") }
	// Never hash original before BlindSign; CIRCL performs the reviewed primitive.
	signature, err := blindrsa.NewSigner(s.key).BlindSign(original)
	if err != nil { return nil, err }
	return map[string]string{"blind_sig":base64.RawURLEncoding.EncodeToString(signature)}, nil
}

func run() error {
	state := &localSigner{}
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte,4096),8192)
	writer := json.NewEncoder(os.Stdout)
	for scanner.Scan() {
		var input request
		decoder := json.NewDecoder(bytes.NewReader(scanner.Bytes()))
		decoder.DisallowUnknownFields()
		err := decoder.Decode(&input)
		if err == nil {
			var trailing any
			if decoder.Decode(&trailing) != io.EOF { err = errors.New("trailing input") }
		}
		var result any
		if err == nil { result, err = state.handle(input) }
		input.Private = ""
		if err != nil {
			_ = writer.Encode(map[string]string{"error":"Signing unavailable"})
			return errors.New("signing failed")
		}
		if err = writer.Encode(result); err != nil { return err }
	}
	return scanner.Err()
}

func main() {
	if run() != nil { os.Exit(1) } // No keys, inputs, or exception internals in logs.
}
