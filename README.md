# DID Manager V1 Smart Contract

## Overview
A decentralized identity (DID) and verifiable credential management system built on Stacks blockchain using Clarity v2. This contract implements SIP009-compliant NFT-based credentials with comprehensive schema management.

## Features
- 🆔 Decentralized Identity (DID) profiles
- 📜 Schema-based credential system
- 🎫 NFT-based verifiable credentials (SIP009)
- 🔐 Role-based issuer permissions
- ⏱️ Time-based credential expiration
- ↩️ Credential revocation system

## Core Functions

### Profile Management
```clarity
(register-profile (name (string-utf8 64)) (uri (string-utf8 256)))
(get-profile (who principal))
```

### Schema Management
```clarity
(create-schema (name (string-utf8 64)) (uri (string-utf8 256)))
(allow-issuer (schema-id uint) (issuer principal))
(revoke-issuer (schema-id uint) (issuer principal))
```

### Credential Operations
```clarity
(issue-credential (schema-id uint) (subject principal) (hash (buff 32)) 
                 (expires-at (optional uint)) (token-uri (string-utf8 256)))
(verify-credential (token-id uint))
(revoke-credential (token-id uint))
```

## Getting Started

1. Deploy the contract to Stacks blockchain
2. Create a schema for your credential type
3. Add authorized issuers to the schema
4. Issue credentials to subjects
5. Verify credentials using the built-in functions

## Testing

```bash
clarinet test tests/did-manager-v1_test.ts
```

## Security Considerations
- Only schema admins can manage issuer permissions
- Only authorized issuers can mint credentials
- Credential revocation restricted to issuer or schema admin
- Built-in expiration mechanism for time-sensitive credentials

