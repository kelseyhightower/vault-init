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
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go/aws"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/s3"

	"cloud.google.com/go/storage"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/cloudkms/v1"
	"google.golang.org/api/option"
)

var (
	vaultAddr         string
	checkInterval     string
	gcsBucketName     string
	s3BucketName      string
	httpClient        http.Client
	kmsKeyId          string
	prefix            string
	unsealKeyFilePath string
	rootTokenFilePath string

	userAgent = fmt.Sprintf("vault-init/0.1.0 (%s)", runtime.Version())
)

const (
	unsealKeyFileName = "unseal-keys.json.enc"
	rootTokenFileName = "root-token.enc"
)

// InitRequest holds a Vault init request.
type InitRequest struct {
	SecretShares    int `json:"secret_shares"`
	SecretThreshold int `json:"secret_threshold"`
}

// InitResponse holds a Vault init response.
type InitResponse struct {
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

// GCPService holds the GCP KMS Service and Storage Client objects.
type GCPService struct {
	kmsService    *cloudkms.Service
	storageClient *storage.Client
}

// AWSService holds the AWS KMS Service and S3 Storage Client objects.
type AWSService struct {
	kmsService     *kms.KMS
	s3Client       *s3.S3
	kmsContext     context.Context
	storageContext context.Context
}

// Service defines the functions a service must implement
type Service interface {
	Initialize()
	Unseal()
}

func main() {
	log.Println("Starting the vault-init service...")

	vaultAddr = os.Getenv("VAULT_ADDR")
	if vaultAddr == "" {
		vaultAddr = "https://127.0.0.1:8200"
	}

	checkInterval = os.Getenv("CHECK_INTERVAL")
	if checkInterval == "" {
		checkInterval = "10"
	}

	i, err := strconv.Atoi(checkInterval)
	if err != nil {
		log.Fatalf("CHECK_INTERVAL is invalid: %s", err)
	}

	checkIntervalDuration := time.Duration(i) * time.Second

	svcType := strings.ToLower(os.Getenv("CLOUD_SERVICE"))
	if svcType != "aws" && svcType != "gcp" {
		log.Fatalf("CLOUD_SERVICE is invalid, allowed values: GCP, AWS")
	}

	kmsKeyId = os.Getenv("KMS_KEY_ID")
	if kmsKeyId == "" {
		log.Fatal("KMS_KEY_ID must be set and not empty")
	}

	prefix = os.Getenv("PREFIX")
	if prefix != "" {
		unsealKeyFilePath = fmt.Sprintf("%s/%s", prefix, unsealKeyFileName)
		rootTokenFilePath = fmt.Sprintf("%s/%s", prefix, rootTokenFileName)
	} else {
		unsealKeyFilePath = unsealKeyFileName
		rootTokenFilePath = rootTokenFileName
	}

	// Create our client and storage contexts
	kmsCtx, kmsCtxCancel := context.WithCancel(context.Background())
	defer kmsCtxCancel()
	storageCtx, storageCtxCancel := context.WithCancel(context.Background())
	defer storageCtxCancel()

	var service Service

	if svcType == "gcp" {
		log.Println("Using GCP Environment")
		gcsBucketName = os.Getenv("GCS_BUCKET_NAME")
		if gcsBucketName == "" {
			log.Fatal("GCS_BUCKET_NAME must be set and not empty")
		}
		kmsClient, err := google.DefaultClient(kmsCtx, "https://www.googleapis.com/auth/cloudkms")
		if err != nil {
			log.Println(err)
			return
		}

		gcpKmsService, err := cloudkms.New(kmsClient)
		if err != nil {
			log.Println(err)
			return
		}
		gcpKmsService.UserAgent = userAgent

		storageClient, err := storage.NewClient(storageCtx,
			option.WithUserAgent(userAgent),
			option.WithScopes(storage.ScopeReadWrite),
		)
		if err != nil {
			log.Fatal(err)
		}

		service = &GCPService{
			kmsService:    gcpKmsService,
			storageClient: storageClient,
		}
	} else {
		log.Println("Using AWS Environment")
		s3BucketName = os.Getenv("S3_BUCKET_NAME")
		if s3BucketName == "" {
			log.Fatal("S3_BUCKET_NAME must be set and not empty ")
		}
		sess, err := session.NewSession()
		if err != nil {
			log.Fatalf("Error creating AWS Session: %s", err)
		}

		service = &AWSService{
			kmsService:     kms.New(sess),
			s3Client:       s3.New(sess),
			kmsContext:     kmsCtx,
			storageContext: storageCtx,
		}
	}

	httpClient = http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	signalCh := make(chan os.Signal)
	signal.Notify(signalCh,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGKILL,
	)

	stop := func() {
		log.Printf("Shutting down")
		kmsCtxCancel()
		storageCtxCancel()
		os.Exit(0)
	}

	for {
		select {
		case <-signalCh:
			stop()
		default:
		}
		response, err := httpClient.Head(vaultAddr + "/v1/sys/health")

		if response != nil && response.Body != nil {
			if err := response.Body.Close(); err != nil {
				log.Fatalf("Error closing response body: %s", err)
			}
		}

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
			service.Initialize()
			service.Unseal()
		case 503:
			log.Println("Vault is sealed. Unsealing...")
			service.Unseal()
		default:
			log.Printf("Vault is in an unknown state. Status code: %d", response.StatusCode)
		}

		log.Printf("Next check in %s", checkIntervalDuration)

		select {
		case <-signalCh:
			stop()
		case <-time.After(checkIntervalDuration):
		}
	}
}

func (s *GCPService) Initialize() {
	initRequest := InitRequest{
		SecretShares:    5,
		SecretThreshold: 3,
	}

	initRequestData, err := json.Marshal(&initRequest)
	if err != nil {
		log.Println(err)
		return
	}

	r := bytes.NewReader(initRequestData)
	request, err := http.NewRequest("PUT", vaultAddr+"/v1/sys/init", r)
	if err != nil {
		log.Println(err)
		return
	}

	response, err := httpClient.Do(request)
	if err != nil {
		log.Println(err)
		return
	}
	defer response.Body.Close()

	initRequestResponseBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Println(err)
		return
	}

	if response.StatusCode != 200 {
		log.Printf("init: non 200 status code: %d", response.StatusCode)
		return
	}

	var initResponse InitResponse

	if err := json.Unmarshal(initRequestResponseBody, &initResponse); err != nil {
		log.Println(err)
		return
	}

	log.Println("Encrypting unseal keys and the root token...")

	rootTokenEncryptRequest := &cloudkms.EncryptRequest{
		Plaintext: base64.StdEncoding.EncodeToString([]byte(initResponse.RootToken)),
	}

	rootTokenEncryptResponse, err := s.kmsService.Projects.Locations.KeyRings.CryptoKeys.Encrypt(kmsKeyId, rootTokenEncryptRequest).Do()
	if err != nil {
		log.Println(err)
		return
	}

	unsealKeysEncryptRequest := &cloudkms.EncryptRequest{
		Plaintext: base64.StdEncoding.EncodeToString(initRequestResponseBody),
	}

	unsealKeysEncryptResponse, err := s.kmsService.Projects.Locations.KeyRings.CryptoKeys.Encrypt(kmsKeyId, unsealKeysEncryptRequest).Do()
	if err != nil {
		log.Println(err)
		return
	}

	bucket := s.storageClient.Bucket(gcsBucketName)

	// Save the encrypted unseal keys.
	ctx := context.Background()
	unsealKeysObject := bucket.Object(unsealKeyFilePath).NewWriter(ctx)
	defer unsealKeysObject.Close()

	_, err = unsealKeysObject.Write([]byte(unsealKeysEncryptResponse.Ciphertext))
	if err != nil {
		log.Println(err)
	}

	log.Printf("Unseal keys written to gs://%s/%s", gcsBucketName, unsealKeyFilePath)

	// Save the encrypted root token.
	rootTokenObject := bucket.Object(rootTokenFilePath).NewWriter(ctx)
	defer rootTokenObject.Close()

	_, err = rootTokenObject.Write([]byte(rootTokenEncryptResponse.Ciphertext))
	if err != nil {
		log.Println(err)
	}

	log.Printf("Root token written to gs://%s/%s", gcsBucketName, rootTokenFilePath)

	log.Println("Initialization complete.")

}
func (s *GCPService) Unseal() {
	bucket := s.storageClient.Bucket(gcsBucketName)

	ctx := context.Background()
	unsealKeysObject, err := bucket.Object(unsealKeyFilePath).NewReader(ctx)
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

	unsealKeysDecryptRequest := &cloudkms.DecryptRequest{
		Ciphertext: string(unsealKeysData),
	}

	unsealKeysDecryptResponse, err := s.kmsService.Projects.Locations.KeyRings.CryptoKeys.Decrypt(kmsKeyId, unsealKeysDecryptRequest).Do()
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
		done, err := unsealOne(key)
		if done {
			return
		}

		if err != nil {
			log.Println(err)
			return
		}
	}
}

func (s *AWSService) Initialize() {
	initRequest := InitRequest{
		SecretShares:    5,
		SecretThreshold: 3,
	}

	initRequestData, err := json.Marshal(&initRequest)
	if err != nil {
		log.Println(err)
		return
	}

	r := bytes.NewReader(initRequestData)
	request, err := http.NewRequest("PUT", vaultAddr+"/v1/sys/init", r)
	if err != nil {
		log.Println(err)
		return
	}

	response, err := httpClient.Do(request)
	if err != nil {
		log.Println(err)
		return
	}
	defer response.Body.Close()

	initRequestResponseBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Println(err)
		return
	}

	if response.StatusCode != 200 {
		log.Printf("init: non 200 status code: %d", response.StatusCode)
		return
	}

	var initResponse InitResponse

	if err := json.Unmarshal(initRequestResponseBody, &initResponse); err != nil {
		log.Println(err)
		return
	}

	log.Println("Encrypting unseal keys and the root token...")

	rootTokenEncryptInput := &kms.EncryptInput{
		Plaintext: []byte(initResponse.RootToken),
		KeyId:     &kmsKeyId,
	}
	rootTokenEncryptOutput, err := s.kmsService.EncryptWithContext(s.kmsContext, rootTokenEncryptInput)
	if err != nil {
		log.Println(err)
		return
	}

	unsealKeysEncryptInput := &kms.EncryptInput{
		Plaintext: []byte(initRequestResponseBody),
		KeyId:     &kmsKeyId,
	}
	unsealKeysEncryptOutput, err := s.kmsService.EncryptWithContext(s.kmsContext, unsealKeysEncryptInput)
	if err != nil {
		log.Println(err)
		return
	}

	// Write the Unseal Keys to S3
	putUnsealKeysInput := &s3.PutObjectInput{
		Key:    aws.String(unsealKeyFilePath),
		Bucket: &s3BucketName,
		Body:   bytes.NewReader(unsealKeysEncryptOutput.CiphertextBlob),
	}

	_, err = s.s3Client.PutObjectWithContext(s.storageContext, putUnsealKeysInput)
	if err != nil {
		log.Println(err)
		return
	}
	log.Printf("Unseal keys written to s3://%s/%s", s3BucketName, unsealKeyFilePath)

	// Write the Root Token to S3
	putRootTokenInput := &s3.PutObjectInput{
		Key:    aws.String(rootTokenFilePath),
		Bucket: &s3BucketName,
		Body:   bytes.NewReader(rootTokenEncryptOutput.CiphertextBlob),
	}

	_, err = s.s3Client.PutObjectWithContext(s.storageContext, putRootTokenInput)
	if err != nil {
		log.Println(err)
		return
	}

	log.Printf("Root token written to s3://%s/%s", s3BucketName, rootTokenFilePath)

	log.Println("Initialization complete.")

}
func (s *AWSService) Unseal() {

	getObjectInput := &s3.GetObjectInput{
		Bucket: &s3BucketName,
		Key:    aws.String(unsealKeyFilePath),
	}
	getObjectOutput, err := s.s3Client.GetObjectWithContext(s.storageContext, getObjectInput)
	if err != nil {
		log.Println(err)
		return
	}
	defer getObjectOutput.Body.Close()
	unsealKeysData, err := ioutil.ReadAll(getObjectOutput.Body)
	if err != nil {
		log.Println(err)
		return
	}

	kmsDecryptInput := &kms.DecryptInput{
		CiphertextBlob: unsealKeysData,
	}
	unsealKeysPlaintext, err := s.kmsService.DecryptWithContext(s.kmsContext, kmsDecryptInput)
	if err != nil {
		log.Println(err)
		return
	}
	var initResponse InitResponse
	if err := json.Unmarshal(unsealKeysPlaintext.Plaintext, &initResponse); err != nil {
		log.Println(err)
		return
	}

	for _, key := range initResponse.KeysBase64 {
		done, err := unsealOne(key)
		if done {
			return
		}

		if err != nil {
			log.Println(err)
			return
		}
	}
}

func unsealOne(key string) (bool, error) {
	unsealRequest := UnsealRequest{
		Key: key,
	}

	unsealRequestData, err := json.Marshal(&unsealRequest)
	if err != nil {
		return false, err
	}

	r := bytes.NewReader(unsealRequestData)
	request, err := http.NewRequest(http.MethodPut, vaultAddr+"/v1/sys/unseal", r)
	if err != nil {
		return false, err
	}

	response, err := httpClient.Do(request)
	if err != nil {
		return false, err
	}
	defer response.Body.Close()

	if response.StatusCode != 200 {
		return false, fmt.Errorf("unseal: non-200 status code: %d", response.StatusCode)
	}

	unsealRequestResponseBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return false, err
	}

	var unsealResponse UnsealResponse
	if err := json.Unmarshal(unsealRequestResponseBody, &unsealResponse); err != nil {
		return false, err
	}

	if !unsealResponse.Sealed {
		return true, nil
	}

	return false, nil
}
