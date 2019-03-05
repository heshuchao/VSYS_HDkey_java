# Hardened Derived Key Management Tool for V-Systems

## About
This tool uses [Bitcoin's BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) for reference, some steps are 
changed to fit the [v-systems](https://github.com/virtualeconomy)' public key generation.
By using this tool, a wallet can calculate the public keys without revealing the private keys, and derived multiple keypair 
chains from a single root.

This tool is based on [`package org.whispersystems.curve25519.java`](https://github.com/icreator/Erachain_public/tree/master/org/whispersystems/curve25519/java) from repository `Erachain_alpha` of organization
`icreator`.

## Difference between VSYS_HDkey and BIP32

### 1. Root key generation

After the root key is generated , a few more operations were performed.
```
i[0] &= 248;
i[31] &= 127;
i[31] |= 64;
```
which is based on the description of elliptic curve cryptography algorithm [Ed25519](http://ed25519.cr.yp.to).

### 2. Extension process


Only the first 28 bytes of `il` are used to generate child keys, which is designed to avoid the child private keys' length 
exceeding the limit of 32 bytes. 

Before added to parent private keys, `il` is multipied by `8`, this can prevent the last 3 bits of private keys been changed.

### 3. Public key generation

The extension process is based on Ed25519 points, meanwhile the v-systems uses X25519 points to generate addresses.So a conversion 
operation is performed, see package `systems.v.hdkey`->class `curve_points`->function `convert_Ed_to_X`.

###4. Other details changes

The boundary value of normal derived and hardened derived is setted to `0x70000000`.
The hash function of parent finger print generation is changed to single `sha256`.
Others...
## How to use

There is an example to show how to derived keys in package `Example`->class `Test`->function `main`.

Three functions are needed to complete a derived process.

1. `ExtendedKey.generateParentPublicKey` returns a base58 encoded string, like this:
```
vsysPubqcFvyLU3S1SC75CEVA3jaJKZTR83Tn74P1pJk2mg3YoymrMWqrn35g7TYoEA8AoCdyohQt8Lj3MhqBZJUKQDmxEE3AVR94L6tUXHx4
```
which should be saved by wallet.
All the child public keys' generation depend on, and only depend on this string.

2. `ExtendedKey.generateChildPublicKeyBytes` returns the v-systems public keys through the above mentioned string.

3. `ExtendedKey.generatePrivateKey` can calculate the corresponding private keys when sign a transaction. 




