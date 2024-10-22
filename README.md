# P2PKH Wallet Implementation
This repository contains an implementation of a hierarchical deterministic (HD) Bitcoin wallet based on the BIP44 standard for generating P2PKH (Pay-to-PubKey-Hash) addresses. The wallet supports both Mainnet and Testnet networks, and provides various utility functions for generating keys, addresses, and validating them.

## Features
- Mnemonic-based wallet generation (BIP39)
- Hierarchical Deterministic (HD) keys (BIP44)
- Support for Mainnet and Testnet
- Public and private key derivation
- Address generation and validation
- Extended public key (xpub) support
- Wallet Import Format (WIF) for private keys

## Table of Contents
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [Wallet Methods](#wallet-methods)
- [Testing](#testing)
- [Contributing](#contributing)
- [License](#license)

## Installation

To use this package, you will need to have Go installed on your system. You can install the package using go get:

```bash
go get github.com/yourusername/p2pkh
```

Then, import it in your Go code:

```go
import "github.com/yourusername/p2pkh"
```

## Usage

You can create a new wallet by providing a mnemonic, network type, and a derivation path.

### Example of creating a new wallet:

```go
package main

import (
"fmt"
"github.com/yourusername/p2pkh"
)

func main() {
config := &p2pkh.Config{
Mnemonic: "romance trash engine during cliff verify tunnel memory vault chief fluid fox",
Path:     `m/44'/0'/0'/0/0`,  // Mainnet derivation path
Network:  p2pkh.NetworkMainnet,
}

    wallet, err := p2pkh.New(config)
    if err != nil {
        fmt.Println("Error creating wallet:", err)
        return
    }

    fmt.Println("Address:", wallet.AddressHex())
    fmt.Println("Public Key:", wallet.PublicKey())
    fmt.Println("Mnemonic:", wallet.Mnemonic())
}
```

## Configuration

### Config Struct

The `Config` struct is used to create a new wallet. It requires the following fields:

- **Mnemonic**: A valid BIP39 mnemonic phrase.
- **Path**: The derivation path (e.g., m/44'/0'/0'/0/0 for Bitcoin Mainnet).
- **Network**: Either NetworkMainnet or NetworkTestnet.

### Example:

```go
config := &p2pkh.Config{
Mnemonic: "romance trash engine during cliff verify tunnel memory vault chief fluid fox",
Path:     `m/44'/1'/0'/0/0`,  // Testnet derivation path
Network:  p2pkh.NetworkTestnet,
}
```

## Wallet Methods

The `Wallet` struct provides the following methods:

- `PublicKey()`: Returns the wallet's ECDSA public key.
- `PrivateKey()`: Returns the wallet's private key in Wallet Import Format (WIF).
- `Address()`: Returns the wallet's P2PKH Bitcoin address (native btcutil format).
- `AddressHex()`: Returns the wallet's Bitcoin address in a hexadecimal string format.
- `ValidateAddress(address string)`: Validates if the provided address belongs to the current network.
- `ExtendedPublicKey()`: Returns the extended public key (xpub).
- `Derive(index interface{})`: Derives a new wallet based on the provided index from the current wallet.

### Example: Retrieving the Private Key

```go
privateKey, err := wallet.PrivateKey()
if err != nil {
fmt.Println("Error retrieving private key:", err)
} else {
fmt.Println("Private Key (WIF):", privateKey)
}
```

### Example: Validating an Address

```go
isValid, err := wallet.ValidateAddress("1QHTz6wMURLy8DT6aeGAVbF2UvtuWZKozr")
if err != nil {
fmt.Println("Error validating address:", err)
} else if isValid {
fmt.Println("Address is valid")
} else {
fmt.Println("Address is invalid")
}
```

## Testing

The package includes a set of unit tests that can be run using the go test command. The tests cover the core functionality of the wallet, including key and address generation, derivation paths, and validation.

To run the tests, simply run:

```bash
go test ./...
```

Example Test

```go
func Test_InvalidMnemonic(t *testing.T) {
config := &p2pkh.Config{
Mnemonic: "invalid mnemonic phrase",
Path:     `m/44'/0'/0'/0`,
Network:  p2pkh.NetworkMainnet,
}

    wallet, err := p2pkh.New(config)
    assert.Nil(t, wallet)
    assert.EqualError(t, err, p2pkh.ErrInvalidMnemonic)
}
```

## Contributing

If you'd like to contribute to this project, feel free to submit a pull request or open an issue on GitHub.

## License

This project is licensed under the MIT License.
