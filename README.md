# win-security-cli

## PCheck - Check if user has a password set on his  desktop
```
win-security-cli.exe p
```
returns 0 if the user doesn't have any password on his desktop
returns 1 if the user have a passwordp on his desktop

## Encrypt - Encrypts stdIn data using Windows DPAPI
```
win-security-cli.exe e "pass some clear top secret data you need to encrypt"
```

returns the encrypted version of the data encoded in base64

## Decrypt - Decrypt stdIn data using Windows DPAPI
```
win-security-cli.exe d "pass some encrypted top secret data you need to decrypt"
```

returns the decrypted version of the data
