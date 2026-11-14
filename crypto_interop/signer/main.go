// Test-only signer: ephemeral RSA keys and a published RFC test key.
// No HTTP, database, business message, serial, or production key-loading API.
package main

import (
    "bufio"
    "bytes"
    "crypto/rand"
    "crypto/rsa"
    "crypto/sha256"
    "crypto/x509"
    "encoding/base64"
    "encoding/hex"
    "encoding/json"
    "flag"
    "fmt"
    "io"
    "math/big"
    "os"
    "strings"

    "github.com/cloudflare/circl/blindsign/blindrsa"
)

type request struct {
    Op string `json:"op"`
    Key string `json:"key"`
    Blinded string `json:"blinded_msg,omitempty"`
}

func integer(value string) *big.Int {
    result, _ := new(big.Int).SetString(strings.TrimPrefix(value, "0x"), 16)
    return result
}

func rfcKey(path string) (*rsa.PrivateKey, error) {
    contents, err := os.ReadFile(path)
    if err != nil { return nil, err }
    var value map[string]string
    if err = json.Unmarshal(contents, &value); err != nil { return nil, err }
    n, e, d, p, q := integer(value["n"]), integer(value["e"]), integer(value["d"]), integer(value["p"]), integer(value["q"])
    if n == nil || e == nil || d == nil || p == nil || q == nil || !e.IsInt64() { return nil, fmt.Errorf("invalid test key") }
    // Refuse arbitrary/private production keys even if this test CLI is misused.
    fingerprint := sha256.Sum256(n.Bytes())
    if hex.EncodeToString(fingerprint[:]) != "1a6cf8eba29dfd29e72e94ea99e91a346a158494b73d3724fb4069a11a57503e" {
        return nil, fmt.Errorf("not the published RFC test modulus")
    }
    key := &rsa.PrivateKey{PublicKey: rsa.PublicKey{N:n, E:int(e.Int64())}, D:d, Primes:[]*big.Int{p,q}}
    if key.N.BitLen() != 4096 || key.E != 65537 { return nil, fmt.Errorf("unexpected RFC key") }
    return key, key.Validate()
}

func respond(req request, keys map[string]*rsa.PrivateKey) (any, error) {
    key := keys[req.Key]
    if key == nil { return nil, fmt.Errorf("unknown test key") }
    switch req.Op {
    case "public":
        if req.Blinded != "" { return nil, fmt.Errorf("unexpected input") }
        der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
        if err != nil { return nil, err }
        return map[string]any{"spki":base64.RawURLEncoding.EncodeToString(der), "bits":key.N.BitLen(), "exponent":key.E}, nil
    case "sign":
        original, err := base64.RawURLEncoding.Strict().DecodeString(req.Blinded)
        if err != nil || base64.RawURLEncoding.EncodeToString(original) != req.Blinded || len(original) != key.Size() {
            return nil, fmt.Errorf("invalid blinded message")
        }
        value := new(big.Int).SetBytes(original)
        if value.Sign() <= 0 || value.Cmp(key.N) >= 0 { return nil, fmt.Errorf("invalid representative") }
        // IMPORTANT: original modulus-sized bytes, NEVER SHA256(original).
        signature, err := blindrsa.NewSigner(key).BlindSign(original)
        if err != nil { return nil, err }
        equalityHash := sha256.Sum256(original) // Diagnostic/equality only.
        return map[string]any{"blind_sig":base64.RawURLEncoding.EncodeToString(signature),
            "input_length":len(original), "input_hash":hex.EncodeToString(equalityHash[:])}, nil
    }
    return nil, fmt.Errorf("unknown operation")
}

func run() error {
    fixture := flag.String("rfc-test-key", "", "Published RFC vector key in an external temporary file")
    flag.Parse()
    if *fixture == "" { return fmt.Errorf("RFC test fixture required") }
    rfc, err := rfcKey(*fixture)
    if err != nil { return err }
    generated, err := rsa.GenerateKey(rand.Reader, 3072)
    if err != nil { return err }
    wrong, err := rsa.GenerateKey(rand.Reader, 3072)
    if err != nil { return err }
    keys := map[string]*rsa.PrivateKey{"rfc":rfc, "generated":generated, "wrong":wrong}
    scanner := bufio.NewScanner(os.Stdin)
    scanner.Buffer(make([]byte, 4096), 131072)
    encoder := json.NewEncoder(os.Stdout)
    for scanner.Scan() {
        var req request
        decoder := json.NewDecoder(bytes.NewReader(scanner.Bytes()))
        decoder.DisallowUnknownFields()
        var response any
        err = decoder.Decode(&req)
        if err == nil {
            var extra any
            if decoder.Decode(&extra) != io.EOF { err = fmt.Errorf("trailing input") }
        }
        if err == nil { response, err = respond(req, keys) }
        if err != nil { response = map[string]string{"error":"Invalid crypto test request"} }
        if err = encoder.Encode(response); err != nil { return err }
    }
    return scanner.Err()
}

func main() {
    if run() != nil { fmt.Fprintln(os.Stderr, "Crypto test signer failed"); os.Exit(1) }
}
