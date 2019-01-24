// https://github.com/alexzava/chacha20poly1305guard
//
// Package chacha20poly1305guard implements the ChaCha20-Poly1305 AEAD 
// and its extended nonce variant XChaCha20-Poly1305 with memguard
// in order to protect the key in memory.
//
// The code is based on https://github.com/codahale/chacha20poly1305


package chacha20poly1305guard

import (
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"errors"

	"github.com/alexzava/chacha20guard"
	"golang.org/x/crypto/poly1305"
	"github.com/awnumar/memguard"
)

var (
	// ErrAuthFailed is returned when the message authentication is invalid due
	// to tampering.
	ErrAuthFailed = errors.New("message authentication failed")

	// ErrInvalidKey is returned when the provided key is the wrong size.
	ErrInvalidKey = errors.New("invalid key size")

	// ErrInvalidNonce is returned when the provided nonce is the wrong size.
	ErrInvalidNonce = errors.New("invalid nonce size")

	// KeySize is the required size of ChaCha20 keys.
	KeySize = chacha20guard.KeySize
)

type chacha20poly1305 struct {
	ek *memguard.LockedBuffer
	isXChaCha bool
}

// NewX returns a XChaCha20Poly1305 AEAD
// The key must be 256-bit long
func NewX(key *memguard.LockedBuffer) (cipher.AEAD, error) {
	if len(key.Buffer()) != KeySize {
		return nil, ErrInvalidKey
	}

	k := new(chacha20poly1305)
	k.ek = key
	k.isXChaCha = true

	return k, nil
}

// New returns a ChaCha20Poly1305 AEAD
// The key must be 256-bit long
func New(key *memguard.LockedBuffer) (cipher.AEAD, error) {
	if len(key.Buffer()) != KeySize {
		return nil, ErrInvalidKey
	}

	k := new(chacha20poly1305)
	k.ek = key
	k.isXChaCha = false

	return k, nil
}

func (k *chacha20poly1305) NonceSize() int {
	if k.isXChaCha {
		return chacha20guard.XNonceSize
	} else {
		return chacha20guard.NonceSize
	}
	
}

func (*chacha20poly1305) Overhead() int {
	return poly1305.TagSize
}

func (k *chacha20poly1305) Seal(dst, nonce, plaintext, data []byte) []byte {
	if len(nonce) != k.NonceSize() {
		panic(ErrInvalidNonce)
	}

	var c cipher.Stream
	var err error
	if k.isXChaCha {
		c, err = chacha20guard.NewX(k.ek, nonce)
		if err != nil {
			panic(err)
		}
	} else {
		c, err = chacha20guard.New(k.ek, nonce)
		if err != nil {
			panic(err)
		}
	}

	// Converts the given key and nonce into 64 bytes of ChaCha20 key stream, the
	// first 32 of which are used as the Poly1305 key.
	subkey := make([]byte, 64)
	c.XORKeyStream(subkey, subkey)

	var poly1305Key [32]byte
	for i := 0; i < 32; i++ {
		poly1305Key[i] = subkey[i]
	}

	ciphertext := make([]byte, len(plaintext))
	c.XORKeyStream(ciphertext, plaintext)

	tag := tag(poly1305Key, ciphertext, data)

	return append(dst, append(ciphertext, tag...)...)
}

func (k *chacha20poly1305) Open(dst, nonce, ciphertext, data []byte) ([]byte, error) {
	if len(nonce) != k.NonceSize() {
		panic(ErrInvalidNonce)
	}

	digest := ciphertext[len(ciphertext)-k.Overhead():]
	ciphertext = ciphertext[0 : len(ciphertext)-k.Overhead()]

	var c cipher.Stream
	var err error
	if k.isXChaCha {
		c, err = chacha20guard.NewX(k.ek, nonce)
		if err != nil {
			panic(err)
		}
	} else {
		c, err = chacha20guard.New(k.ek, nonce)
		if err != nil {
			panic(err)
		}
	}

	// Converts the given key and nonce into 64 bytes of ChaCha20 key stream, the
	// first 32 of which are used as the Poly1305 key.
	subkey := make([]byte, 64)
	c.XORKeyStream(subkey, subkey)

	var poly1305Key [32]byte
	for i := 0; i < 32; i++ {
		poly1305Key[i] = subkey[i]
	}

	tag := tag(poly1305Key, ciphertext, data)

	if subtle.ConstantTimeCompare(tag, digest) != 1 {
		return nil, ErrAuthFailed
	}

	plaintext := make([]byte, len(ciphertext))
	c.XORKeyStream(plaintext, ciphertext)

	return append(dst, plaintext...), nil
}

func tag(key [32]byte, ciphertext, data []byte) []byte {
	m := make([]byte, len(ciphertext)+len(data)+8+8)
	copy(m[0:], data)
	binary.LittleEndian.PutUint64(m[len(data):], uint64(len(data)))

	copy(m[len(data)+8:], ciphertext)
	binary.LittleEndian.PutUint64(m[len(data)+8+len(ciphertext):],
		uint64(len(ciphertext)))

	var out [poly1305.TagSize]byte
	poly1305.Sum(&out, m, &key)

	return out[0:]
}