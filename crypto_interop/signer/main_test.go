package main

import (
    "crypto/rand"
    "crypto/rsa"
    "encoding/base64"
    "testing"
)

func TestRejectsDigestInsteadOfBlindedMessage(t *testing.T) {
    key, err := rsa.GenerateKey(rand.Reader, 3072)
    if err != nil { t.Fatal("test key generation failed") }
    _, err = respond(request{Op:"sign", Key:"generated", Blinded:base64.RawURLEncoding.EncodeToString(make([]byte,32))},
        map[string]*rsa.PrivateKey{"generated":key})
    if err == nil { t.Fatal("a SHA256-sized input must never reach BlindSign") }
}
