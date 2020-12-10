package reference

import (
	"fmt"
	"github.com/monax/hoard/v8/protodet"
)

func New(address, secretKey, salt []byte, size int64) *Ref {
	if len(salt) == 0 {
		salt = nil
	}
	return &Ref{
		Address:   address,
		SecretKey: secretKey,
		Salt:      salt,
		Size_:     size,
	}
}

// Obtain the canonical plaintext for the Ref with an optional nonce that can be
// be used to salt the plaintext in order to obtain an unpredictable version of
// the plaintext for encryption purposes (i.e. for Grants). The nonce is
// discarded when read by FromPlaintext
func PlaintextFromRefs(refs []*Ref, nonce []byte) ([]byte, error) {
	refsWithNonce := &RefsWithNonce{
		Refs:  refs,
		Nonce: nonce,
	}
	bs, err := protodet.Marshal(refsWithNonce)
	if err != nil {
		return nil, fmt.Errorf("error while marshalling to plaintext, error supressed for security")
	}
	return bs, nil
}

func MustPlaintextFromRefs(refs []*Ref, nonce []byte) []byte {
	bs, err := PlaintextFromRefs(refs, nonce)
	if err != nil {
		panic(err)
	}
	return bs
}

func RefsFromPlaintext(plaintext []byte, version int32) ([]*Ref, error) {
	wrapper := new(RefsWithNonce)
	err := protodet.Unmarshal(plaintext, wrapper)
	if err != nil {
		return nil, fmt.Errorf("error while unmarshalling from plaintexst, error supressed for security")
	}
	return wrapper.Refs, nil
}

func MustRefsFromPlaintext(plaintext []byte, version int32) []*Ref {
	refs, err := RefsFromPlaintext(plaintext, version)
	if err != nil {
		panic(err)
	}
	return refs
}
