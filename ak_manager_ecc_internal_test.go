package tpm

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/google/go-tpm/tpm2"
)

func eccPublic(curveID tpm2.TPMECCCurve, x, y []byte) *tpm2.TPMTPublic {
	return &tpm2.TPMTPublic{
		Type: tpm2.TPMAlgECC,
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
			CurveID: curveID,
		}),
		Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{
			X: tpm2.TPM2BECCParameter{Buffer: x},
			Y: tpm2.TPM2BECCParameter{Buffer: y},
		}),
	}
}

// A TPM reports the coordinates with leading zeros stripped, so the shortest
// keys in a random sample are the ones that used to be padded by big.Int and
// now have to be padded by hand.
func TestPublicKeyFromTPMTPublicECC(t *testing.T) {
	for _, tc := range []struct {
		name    string
		curveID tpm2.TPMECCCurve
		curve   elliptic.Curve
	}{
		{"P256", tpm2.TPMECCNistP256, elliptic.P256()},
		{"P384", tpm2.TPMECCNistP384, elliptic.P384()},
		{"P521", tpm2.TPMECCNistP521, elliptic.P521()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for i := 0; i < 50; i++ {
				priv, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
				if err != nil {
					t.Fatal(err)
				}

				got, err := publicKeyFromTPMTPublic(eccPublic(tc.curveID, priv.X.Bytes(), priv.Y.Bytes()))
				if err != nil {
					t.Fatalf("converting a %s key: %v", tc.name, err)
				}

				pub, ok := got.(*ecdsa.PublicKey)
				if !ok {
					t.Fatalf("got %T, want *ecdsa.PublicKey", got)
				}
				if !pub.Equal(&priv.PublicKey) {
					t.Fatal("converted key does not match the original")
				}
			}
		})
	}
}

func TestPublicKeyFromTPMTPublicRejectsBadECCPoints(t *testing.T) {
	for _, tc := range []struct {
		name string
		x, y []byte
	}{
		{"off the curve", []byte{1}, []byte{2}},
		{"coordinate too long", make([]byte, 33), make([]byte, 32)},
		{"point at infinity", nil, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := publicKeyFromTPMTPublic(eccPublic(tpm2.TPMECCNistP256, tc.x, tc.y)); err == nil {
				t.Fatal("expected an error, got none")
			}
		})
	}
}
