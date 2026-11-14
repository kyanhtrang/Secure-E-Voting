package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"testing"

	"github.com/cloudflare/circl/blindsign/blindrsa"
)

func TestBootAndOriginalBlindedBytes(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader,3072)
	if err != nil { t.Fatal("key generation failed") }
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil { t.Fatal("key encoding failed") }
	signer := &localSigner{}
	_, err = signer.handle(request{Op:"init", KeyID:"test-ra", Private:base64.RawURLEncoding.EncodeToString(der)})
	clear(der)
	if err != nil { t.Fatal("bootstrap failed") }
	client, err := blindrsa.NewClient(blindrsa.SHA384PSSRandomized,&key.PublicKey)
	if err != nil { t.Fatal("client setup failed") }
	prepared, err := client.Prepare(rand.Reader,[]byte("public synthetic client message"))
	if err != nil { t.Fatal("prepare failed") }
	blinded, state, err := client.Blind(rand.Reader,prepared)
	if err != nil { t.Fatal("blind failed") }
	result, err := signer.handle(request{Op:"sign", KeyID:"test-ra", Blinded:base64.RawURLEncoding.EncodeToString(blinded)})
	if err != nil { t.Fatal("signing failed") }
	blindSignature, err := decode(result.(map[string]string)["blind_sig"])
	if err != nil { t.Fatal("response failed") }
	if _, err = client.Finalize(state,blindSignature); err != nil { t.Fatal("finalize failed") }
	if _, err = signer.handle(request{Op:"sign",KeyID:"test-ra",Blinded:base64.RawURLEncoding.EncodeToString(make([]byte,32))}); err == nil {
		t.Fatal("a digest must not be signed")
	}
	if _, err = signer.handle(request{Op:"sign",KeyID:"wrong-key",Blinded:base64.RawURLEncoding.EncodeToString(blinded)}); err == nil {
		t.Fatal("key substitution accepted")
	}
	if _, err = signer.handle(request{Op:"init",KeyID:"test-ra",Private:"replacement"}); err == nil {
		t.Fatal("reinitialization accepted")
	}
}
