# JWKS Server Project Overview

This project implements a secure JWKS server using FastAPI, designed to simulate real-world authentication infrastructure for issuing and verifying JWTs. It incorporates modern security practices like key encryption, user authentication, and rate limiting.

## Core Features

- **RSA Key Management**: The server automatically generates RSA private keys, encrypts them using AES encryption, and stores them securely in a SQLite database. Only the public portions of the keys are exposed via the .json endpoint.

- **JWT Signing and Verification**: Users can register and authenticate to receive signed JWTs. The server signs tokens with private keys stored in the database and verifies tokens using the corresponding public keys.

- **Secure Storage**: Private keys are encrypted at rest using AES encryption with a securely loaded key from environment variables, enhancing protection against unauthorized database access.

- **User Registration and Login**: New users can register with a username and email. Upon registration, users receive a randomly generated password hashed with Argon2. Authentication generates JWT access tokens tied to their accounts.

- **Authentication Logging**: All successful authentication attempts are logged with timestamps and client IP addresses to a logs table for auditing purposes.


## Security Measures

- AES encryption of private keys
- Argon2 password hashing for user credentials
- Strict token expiration and issuance claims
- Protection against excessive login attempts

## Purpose

The primary goal of this project is to demonstrate how a secure authentication server can manage cryptographic keys, authenticate users, issue JWTs, and expose public keys for verification in a safe, scalable way. It simulates key components of production-grade identity providers while being lightweight and educational.

