
# AntiPhish

A defensive Python-based phishing detection and URL analysis tool designed to identify suspicious URLs and potential phishing indicators.

> **Safety:** This project is intended for cybersecurity education, defensive analysis, and authorized security testing. It does not perform credential collection, phishing attacks, or malicious activity.

## Project Overview

Phishing is one of the most common cybersecurity threats used to trick users into revealing sensitive information such as usernames, passwords, financial information, or authentication codes.

AntiPhish analyzes URLs and identifies characteristics commonly associated with phishing attempts.

The project focuses on defensive analysis rather than executing or interacting with suspicious websites.

## Objectives

The main objectives of this project are:

- Analyze suspicious URLs
- Detect suspicious domains
- Identify URL obfuscation
- Detect IP-based URLs
- Detect excessive subdomains
- Identify suspicious URL keywords
- Detect URL shortening services
- Check HTTPS usage
- Calculate URL characteristics
- Generate a risk score
- Classify URLs as Low, Medium, or High Risk
- Generate JSON security reports

## Features

### URL Analysis

AntiPhish analyzes different characteristics of a URL, including:

- URL length
- Domain length
- Number of subdomains
- HTTPS usage
- IP address usage
- Suspicious keywords
- URL encoding
- Special characters
- Suspicious TLDs
- URL shorteners

### Suspicious Keyword Detection

The tool checks for keywords commonly associated with phishing.

Examples:

- login
- verify
- verification
- account
- password
- secure
- update
- banking
- wallet
- signin
- authentication

A keyword alone does not prove that a URL is malicious.

## IP Address Detection

Attackers may sometimes use an IP address instead of a normal domain name.

Example:

```text
http://192.168.1.10/login