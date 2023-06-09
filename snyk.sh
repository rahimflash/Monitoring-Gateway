#!/bin/bash

# Dependencies to install:
# For apt:
sudo apt-get install jq
# For yum:
# $ sudo yum install jq

access_token=$(curl --location --request POST 'https://api.getport.io/v1/auth/access_token' --header 'Content-Type: application/json' --data-raw '{
	"clientId": "evsAbApsoq03nWxFwVDzLMzfkcxQR4ig",
	"clientSecret": "PhTXM94NosSJoDawh9fD5YbMswck1iEp1eKxvuHDgirKarvW2bC75OGXZoDbQBLp"
}' | jq '.accessToken' | sed 's/"//g')

# The token will be available in the access_token variable

blueprint_id='snykVulnerability'

curl --location --request POST "https://api.getport.io/v1/blueprints/${blueprint_id}/entities?upsert=true" 	--header "Authorization: Bearer $access_token" 	--header "Content-Type: application/json" 	--data-raw '{
	"identifier": "Tui",
	"title": "Wuni",
	"properties": {"organizationUrl":"https://app.snyk.io/org/twumgilbert7/","organizationName":"string","projectName":"string","projectOrigin":"string","branchName":"string","pkgName":"string","issueType":"string","issueSeverity":"string","issueURL":"https://example.com","issueStatus":"added","projectID":"string"},
	"relations": {}
}'

# The output of the command contains the content of the resulting blueprint






























































c
