// Copyright 2018 Google Inc. All Rights Reserved.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"cloud.google.com/go/storage"
	"golang.org/x/oauth2/google"
	cloudkms "google.golang.org/api/cloudkms/v1"
)

var (
	checkInterval string
	gcsBucketName string
	httpClient    http.Client
	kmsKeyId      string
	storageClient *storage.Client
)

// InitRequest holds a Vault init request.
type InitRequest struct {
	SecretShares    int `json:"secret_shares"`
	SecretThreshold int `json:"secret_threshold"`
}

// InitResponse holds a Vault init response.
type InitResponse struct {
	Keys       []string `json:"keys"`
	KeysBase64 []string `json:"keys_base64"`
	RootToken  string   `json:"root_token"`
}

// UnsealRequest holds a Vault unseal request.
type UnsealRequest struct {
	Key   string `json:"key"`
	Reset bool   `json:"reset"`
}

// UnsealResponse holds a Vault unseal response.
type UnsealResponse struct {
	Sealed   bool `json:"sealed"`
	T        int  `json:"t"`
	N        int  `json:"n"`
	Progress int  `json:"progress"`
}

func main() {
	log.Println("Starting the vault-init service...")

	checkInterval = os.Getenv("CHECK_INTERVAL")
	if checkInterval == "" {
		checkInterval = "10"
	}

	i, err := strconv.Atoi(checkInterval)
	if err != nil {
		log.Fatalf("CHECK_INTERVAL is invalid: %s", err)
	}

	checkIntervalDuration := time.Duration(i) * time.Second

	gcsBucketName = os.Getenv("GCS_BUCKET_NAME")
	if gcsBucketName == "" {
		log.Fatal("GCS_BUCKET_NAME must be set and not empty")
	}

	kmsKeyId = os.Getenv("KMS_KEY_ID")
	if kmsKeyId == "" {
		log.Fatal("KMS_KEY_ID must be set and not empty")
	}

	ctx := context.Background()
	storageClient, err = storage.NewClient(ctx)
	if err != nil {
		log.Fatal(err)
	}

	httpClient = http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	for {
		response, err := httpClient.Head("https://127.0.0.1:8200/v1/sys/health")
		if err != nil {
			log.Println(err)
			time.Sleep(checkIntervalDuration)
			continue
		}

		switch response.StatusCode {
		case 200:
			log.Println("Vault is initialized and unsealed.")
		case 429:
			log.Println("Vault is unsealed and in standby mode.")
		case 501:
			log.Println("Vault is not initialized. Initializing and unsealing...")
			initialize()
			unseal()
		case 503:
			log.Println("Vault is sealed. Unsealing...")
			unseal()
		default:
			log.Printf("Vault is in an unknown state. Status code: %s", response.StatusCode)
		}

		log.Printf("Next check in %s", checkIntervalDuration)
		time.Sleep(checkIntervalDuration)
	}
}

func initialize() {
	initRequest := InitRequest{
		SecretShares:    5,
		SecretThreshold: 3,
	}

	initRequestData, err := json.Marshal(&initRequest)
	if err != nil {
		log.Println(err)
		return
	}

	request, err := http.NewRequest("PUT", "https://127.0.0.1:8200/v1/sys/init", bytes.NewReader(initRequestData))
	if err != nil {
		log.Println(err)
		return
	}

	response, err := httpClient.Do(request)
	if err != nil {
		log.Println(err)
		return
	}

	initRequestResponseBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Println(err)
		return
	}
	defer response.Body.Close()

	if response.StatusCode != 200 {
		log.Printf("Non 200 status code: %s", response.StatusCode)
		return
	}

	var initResponse InitResponse

	if err := json.Unmarshal(initRequestResponseBody, &initResponse); err != nil {
		log.Println(err)
		return
	}

	ctx := context.Background()
	googleDefaultClient, err := google.DefaultClient(ctx, cloudkms.CloudPlatformScope)
	if err != nil {
		log.Println(err)
		return
	}

	kmsService, err := cloudkms.New(googleDefaultClient)
	if err != nil {
		log.Println(err)
		return
	}

	log.Println("Encrypting unseal keys and the root token...")

	rootTokenEncryptRequest := &cloudkms.EncryptRequest{
		Plaintext: base64.StdEncoding.EncodeToString([]byte(initResponse.RootToken)),
	}

	rootTokenEncryptResponse, err := kmsService.Projects.Locations.KeyRings.CryptoKeys.Encrypt(kmsKeyId, rootTokenEncryptRequest).Do()
	if err != nil {
		log.Println(err)
		return
	}

	unsealKeysEncryptRequest := &cloudkms.EncryptRequest{
		Plaintext: base64.StdEncoding.EncodeToString(initRequestResponseBody),
	}

	unsealKeysEncryptResponse, err := kmsService.Projects.Locations.KeyRings.CryptoKeys.Encrypt(kmsKeyId, unsealKeysEncryptRequest).Do()
	if err != nil {
		log.Println(err)
		return
	}

	bucket := storageClient.Bucket(gcsBucketName)

	// Save the encrypted unseal keys.
	ctx = context.Background()
	unsealKeysObject := bucket.Object("unseal-keys.json.enc").NewWriter(ctx)
	defer unsealKeysObject.Close()

	_, err = unsealKeysObject.Write([]byte(unsealKeysEncryptResponse.Ciphertext))
	if err != nil {
		log.Println(err)
	}

	log.Printf("Unseal keys written to gs://%s/%s", gcsBucketName, "unseal-keys.json.enc")

	// Save the encrypted root token.
	rootTokenObject := bucket.Object("root-token.enc").NewWriter(ctx)
	defer rootTokenObject.Close()

	_, err = rootTokenObject.Write([]byte(rootTokenEncryptResponse.Ciphertext))
	if err != nil {
		log.Println(err)
	}

	log.Printf("Root token written to gs://%s/%s", gcsBucketName, "root-token.enc")

	log.Println("Initialization complete.")
}

func unseal() {
	bucket := storageClient.Bucket(gcsBucketName)

	ctx := context.Background()
	unsealKeysObject, err := bucket.Object("unseal-keys.json.enc").NewReader(ctx)
	if err != nil {
		log.Println(err)
		return
	}

	defer unsealKeysObject.Close()

	unsealKeysData, err := ioutil.ReadAll(unsealKeysObject)
	if err != nil {
		log.Println(err)
		return
	}

	ctx = context.Background()
	googleDefaultClient, err := google.DefaultClient(ctx, cloudkms.CloudPlatformScope)
	if err != nil {
		log.Println(err)
		return
	}

	kmsService, err := cloudkms.New(googleDefaultClient)
	if err != nil {
		log.Println(err)
		return
	}

	unsealKeysDecryptRequest := &cloudkms.DecryptRequest{
		Ciphertext: string(unsealKeysData),
	}

	unsealKeysDecryptResponse, err := kmsService.Projects.Locations.KeyRings.CryptoKeys.Decrypt(kmsKeyId, unsealKeysDecryptRequest).Do()
	if err != nil {
		log.Println(err)
		return
	}

	var initResponse InitResponse

	unsealKeysPlaintext, err := base64.StdEncoding.DecodeString(unsealKeysDecryptResponse.Plaintext)
	if err != nil {
		log.Println(err)
		return
	}

	if err := json.Unmarshal(unsealKeysPlaintext, &initResponse); err != nil {
		log.Println(err)
		return
	}

	for _, key := range initResponse.KeysBase64 {
		unsealRequest := UnsealRequest{
			Key: key,
		}

		unsealRequestData, err := json.Marshal(&unsealRequest)
		if err != nil {
			log.Println(err)
			break
		}

		request, err := http.NewRequest("PUT", "https://127.0.0.1:8200/v1/sys/unseal", bytes.NewReader(unsealRequestData))
		if err != nil {
			log.Println(err)
			break
		}

		response, err := httpClient.Do(request)
		if err != nil {
			log.Println(err)
			break
		}

		if response.StatusCode != 200 {
			log.Printf("Non 200 status code: %s", response.StatusCode)
			break
		}

		unsealRequestResponseBody, err := ioutil.ReadAll(response.Body)
		if err != nil {
			log.Println(err)
			break
		}
		defer response.Body.Close()

		var unsealResponse UnsealResponse
		if err := json.Unmarshal(unsealRequestResponseBody, &unsealResponse); err != nil {
			log.Println(err)
			break
		}

		if !unsealResponse.Sealed {
			log.Println("Unseal complete.")
			break
		}
	}
}
