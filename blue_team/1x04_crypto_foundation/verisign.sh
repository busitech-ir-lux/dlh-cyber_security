#! /bin/bash
read -p "Enter method(verify or sign): " method
if [ $method == "verify" ]; then
	read -p "Enter file path: " filePath
	read -p "Enter signature path: " sigPath
	read -p "Enter public key: " pubKey
	if [ openssl dgst -sha256 -verify $pubKey -signature $sigPath $filePath ]; then
		echo "File is successfully verified"
		exit 0
	else echo "Error verifying the signature"
	fi
elif [ $method == "sign" ]; then
	echo "You are going to sign a file"
	exit 0
fi

