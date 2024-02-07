#!/bin/bash

key="9baf7d5cac4141c8cb8cfa3fd270fc4beea0cd540a54250ad88f8f94cb400f91"
ciphertext_hex="af7138ad9608c914bebdfe19be9f2825bd98a70ffd3a4558188f8d8ef8bb1566735f0b618135beb50d80c90000000000"
decryptedtext_hex=$(echo -n "$ciphertext_hex" | xxd -r -p | openssl enc -d -aes-256-ctr -K $key | xxd -p)

decryptedtext=$(echo -n "$decryptedtext_hex" | xxd -r -p)
echo "Decrypted Text: $decryptedtext"
