package p2pkh

import (
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/ethereum/go-ethereum/accounts"
	bip39 "github.com/tyler-smith/go-bip39"
)

// Network represents the type of blockchain network the wallet operates on.
// It can either be "mainnet" for the production Bitcoin network or "testnet"
// for the test Bitcoin network, allowing for separate configurations and
// behaviors for each network.
type Network string

const (
	NetworkMainnet Network = "mainnet"
	NetworkTestnet Network = "testnet"

	ErrInvalidMnemonic  = "mnemonic is required"
	ErrUnsupportedNet   = "unsupported network type: choose either 'mainnet' or 'testnet'"
	ErrInvalidPath      = "failed to parse derivation path"
	ErrKeyDerivation    = "failed to derive key"
	ErrIndexNegative    = "index cannot be negative"
	ErrUnsupportedIndex = "unsupported index type"
)

// Config represents the configuration necessary to create a Wallet.
type Config struct {
	Mnemonic string
	Path     string
	Network  Network
}

// Wallet represents an HD wallet.
type Wallet struct {
	mnemonic    string
	path        string
	root        *hdkeychain.ExtendedKey
	extendedKey *hdkeychain.ExtendedKey
	publicKey   *btcec.PublicKey
	address     *btcutil.AddressPubKey
	params      *chaincfg.Params
}

// New creates a new Wallet from a configuration.
func New(config *Config) (*Wallet, error) {
	if config.Mnemonic == "" || !validateMnemonic(config.Mnemonic) {
		return nil, errors.New(ErrInvalidMnemonic)
	}

	path, err := selectDerivationPath(config.Network, config.Path)
	if err != nil {
		return nil, err
	}
	config.Path = path

	params, err := selectNetworkParams(config.Network)
	if err != nil {
		return nil, err
	}

	seed := bip39.NewSeed(config.Mnemonic, "")

	masterKey, err := generateMasterKey(seed, params)
	if err != nil {
		return nil, err
	}

	key, err := deriveKeyFromPath(masterKey, config.Path)
	if err != nil {
		return nil, err
	}

	publicKey, err := key.ECPubKey()
	if err != nil {
		return nil, err
	}

	addr, err := btcutil.NewAddressPubKey(publicKey.SerializeCompressed(), params)
	if err != nil {
		return nil, err
	}

	return &Wallet{
		mnemonic:    config.Mnemonic,
		path:        config.Path,
		root:        masterKey,
		extendedKey: key,
		publicKey:   publicKey,
		address:     addr,
		params:      params,
	}, nil
}

// selectDerivationPath selects the bypass path based on the network.
func selectDerivationPath(network Network, path string) (string, error) {
	if path == "" {
		switch network {
		case NetworkMainnet:
			return `m/44'/0'/0'/0`, nil
		case NetworkTestnet:
			return `m/44'/1'/0'/0`, nil
		default:
			return "", errors.New(ErrUnsupportedNet)
		}
	}
	return path, nil
}

// selectNetworkParams selects network parameters based on configuration.
func selectNetworkParams(network Network) (*chaincfg.Params, error) {
	switch network {
	case NetworkMainnet:
		return &chaincfg.MainNetParams, nil
	case NetworkTestnet:
		return &chaincfg.TestNet3Params, nil
	default:
		return nil, errors.New(ErrUnsupportedNet)
	}
}

// generateMasterKey generates the master key from the seed and network parameters.
func generateMasterKey(seed []byte, params *chaincfg.Params) (*hdkeychain.ExtendedKey, error) {
	masterKey, err := hdkeychain.NewMaster(seed, params)
	if err != nil {
		return nil, fmt.Errorf("failed to generate master key: %w", err)
	}
	return masterKey, nil
}

// deriveKeyFromPath derives a key from the specified derivation path.
func deriveKeyFromPath(masterKey *hdkeychain.ExtendedKey, path string) (*hdkeychain.ExtendedKey, error) {
	dpath, err := accounts.ParseDerivationPath(path)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ErrInvalidPath, err)
	}

	key := masterKey
	for _, n := range dpath {
		key, err = key.Derive(n)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", ErrKeyDerivation, err)
		}
	}
	return key, nil
}

// convertToUint32 converts different index types to uint32.
func convertToUint32(index interface{}) (uint32, error) {
	switch v := index.(type) {
	case int:
		if v < 0 {
			return 0, errors.New(ErrIndexNegative)
		}
		return uint32(v), nil
	case int64:
		if v < 0 {
			return 0, errors.New(ErrIndexNegative)
		}
		return uint32(v), nil
	case uint, uint32:
		return uint32(v.(uint32)), nil
	default:
		return 0, errors.New(ErrUnsupportedIndex)
	}
}

// Derive derives a new portfolio from an index.
func (s *Wallet) Derive(index interface{}) (*Wallet, error) {
	idx, err := convertToUint32(index)
	if err != nil {
		return nil, err
	}

	derivedKey, err := s.extendedKey.Derive(idx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ErrKeyDerivation, err)
	}

	publicKey, err := derivedKey.ECPubKey()
	if err != nil {
		return nil, err
	}

	addr, err := btcutil.NewAddressPubKey(publicKey.SerializeCompressed(), s.params)
	if err != nil {
		return nil, err
	}

	return &Wallet{
		path:        fmt.Sprintf("%s/%d", s.path, idx),
		root:        s.extendedKey,
		extendedKey: derivedKey,
		address:     addr,
		params:      s.params,
	}, nil
}

// PublicKey returns the public key (ECDSA) associated with the wallet.
func (s *Wallet) PublicKey() *btcec.PublicKey {
	return s.publicKey
}

// Address returns the Bitcoin P2PKH address (AddressPubKey) associated with the wallet's public key.
// This address is in the native format of the btcutil library.
func (s *Wallet) Address() *btcutil.AddressPubKey {
	return s.address
}

// AddressHex returns the Bitcoin address in its encoded hexadecimal string format.
// This is a human-readable format used for transactions and sharing the address.
func (s *Wallet) AddressHex() string {
	return s.Address().EncodeAddress()
}

// Path returns the derivation path used to generate the wallet.
func (s *Wallet) Path() string {
	return s.path
}

// PrivateKey returns the private key associated with the wallet in WIF (Wallet Import Format).
func (s *Wallet) PrivateKey() (string, error) {
	privateKey, err := s.extendedKey.ECPrivKey()
	if err != nil {
		return "", err
	}
	wif, err := btcutil.NewWIF(privateKey, s.params, true)
	if err != nil {
		return "", err
	}
	return wif.String(), nil
}

// ValidateAddress checks if the provided address is valid for the current network.
func (s *Wallet) ValidateAddress(address string) (bool, error) {
	addr, err := btcutil.DecodeAddress(address, s.params)
	if err != nil {
		return false, err
	}
	return addr.IsForNet(s.params), nil
}

// ExtendedPublicKey returns the wallet's extended public key (xpub).
func (s *Wallet) ExtendedPublicKey() (string, error) {
	xpub, err := s.extendedKey.Neuter()
	if err != nil {
		return "", err
	}
	return xpub.String(), nil
}

// Mnemonic returns the mnemonic phrase used to generate the wallet.
func (s *Wallet) Mnemonic() string {
	return s.mnemonic
}

// ValidateMnemonic checks if the given mnemonic is valid according to BIP39.
func validateMnemonic(mnemonic string) bool {
	return bip39.IsMnemonicValid(mnemonic)
}
