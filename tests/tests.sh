#!/bin/sh

test1="Asymmetric encryption test"
test2="Asymmetric decryption test"
test3="Symmetric encryption test"
test4="Symmetric decryption test"
test5="Signing test"
test6="Signature verification test"


# Test asymmetric encryption 
if echo "password" | ./../jfpg -S -e -f file.txt \
	-p test-encryption-pubkey.curve25519 \
	-k test-encryption-secretkey.curve25519 > /dev/null 2>&1; then
	
	echo "$test1 PASSED"
else
	echo "$test1 FAILED"
	exit 1
fi



# Test asymmetric decryption
if echo "password" | ./../jfpg -S -d -f file.txt.jfpg \
	-p test-encryption-pubkey.curve25519 \
	-k test-encryption-secretkey.curve25519 > /dev/null 2>&1; then
	
	echo "$test2 PASSED"
else
	echo "$test2 FAILED"
	exit 1
fi


# Test symmetric encryption
if echo "password" | ./../jfpg -S -c -f file.txt -m 56 > /dev/null 2>&1; then
	echo "$test3 PASSED"
else
	echo "$test3 FAILED"
	exit 1
fi



# Test symmetric decryption
if echo "password" | ./../jfpg -S -d -f file.txt.jfpg > /dev/null 2>&1; then
	echo "$test4 PASSED"
else
	echo "$test4 FAILED"
	exit 1
fi



# Test signing
if echo "password" | ./../jfpg -S -s -f file.txt \
	-k test-signing-secretkey.ed25519 > /dev/null 2>&1; then
	
	echo "$test5 PASSED"
else
	echo "$test5 FAILED"
	exit 1
fi



# Test signature verification
if ./../jfpg -v -f file.txt.signed -p test-signing-pubkey.ed25519 > /dev/null 2>&1; then
	echo "$test6 PASSED"
else
	echo "$test6 FAILED"
	exit 1
fi

# Clean up
rm file.txt.jfpg
rm file.txt.signed

echo "All tests passed successfully!"
