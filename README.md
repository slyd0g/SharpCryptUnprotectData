# SharpCryptUnprotectData

![SharpCryptUnprotectData](https://raw.githubusercontent.com/slyd0g/SharpCryptUnprotectData/master/example.png)

## Description
Use ```CryptUnprotectData()``` to decrypt DPAPI encrypted data on Windows using your current user context. Might be handy if you don't have the domain backup key or the user's password. Pass in b64 encoded + DPAPI encrypted blob, decrypt, get b64 encoded + decrypted blob, profit. Can write output to a file if you've converted this to shellcode using something like Donut and are executing it that way.