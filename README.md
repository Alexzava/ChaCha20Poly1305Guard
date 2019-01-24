# ChaCha20Poly1305Guard

A pure Go implementation of ChaCha20Poly1305 and its extended nonce variant XChaCha20Poly1305 with [MemGuard](https://github.com/awnumar/memguard) in order to protect the key in memory.

Before using read the [Warning](README.md#Warning)

The implementation is based on [https://github.com/codahale/chacha20poly1305](https://github.com/codahale/chacha20poly1305)


## Download/Install
```
go get -u github.com/alexzava/chacha20poly1305guard
```

## Usage

### Import
```
import (
	"fmt"	
	"log"
	"crypto/rand"

	"github.com/awnumar/memguard"
	"github.com/alexzava/chacha20poly1305guard"
)
```

### ChaCha20Poly1305

```
	message := []byte("Hello World!")
	
	//Generate random nonce
	nonce := make([]byte, 8)
	_, err := rand.Read(nonce)
	if err != nil {
		log.Fatal(err)
	}

	//Generate random encryption key with memguard
	key, err := memguard.NewImmutableRandom(32)
	if err != nil {
		log.Println(err)
		memguard.SafeExit(1)
	}
	defer key.Destroy()

	c, err := chacha20poly1305guard.New(key)
	if err != nil {
		log.Fatal(err)
	}

	//Encrypt
	ciphertext := c.Seal(nil, nonce, message, nil)
	fmt.Printf("%x\n", ciphertext)

	//Decrypt
	plaintext, err := c.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s\n", plaintext)
```

### XChaCha20Poly1305

```
	message := []byte("Hello World!")

	//Generate random nonce
	nonce := make([]byte, 24)
	_, err := rand.Read(nonce)
	if err != nil {
		log.Fatal(err)
	}

	//Generate random encryption key with memguard
	key, err := memguard.NewImmutableRandom(32)
	if err != nil {
		log.Println(err)
		memguard.SafeExit(1)
	}
	defer key.Destroy()

	c, err := chacha20poly1305guard.NewX(key)
	if err != nil {
		log.Fatal(err)
	}

	//Encrypt
	ciphertext := c.Seal(nil, nonce, message, nil)
	fmt.Printf("%x\n", ciphertext)

	//Decrypt
	plaintext, err := c.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s\n", plaintext)
```

## Warning

The code may contain bugs or vulnerabilities, currently they have not been found but this does not guarantee absolute security.

Check the repository often because the code could be updated frequently.

## Notes

If you find bugs or vulnerabilities please let me know so they can be fixed.

If you want to help improve the code contact me.

## License

This project is licensed under MIT License - see the [LICENSE](LICENSE) file for details.