# Decentralized Identity Verification Gateway Smart Contract

A blockchain-based biometric identity management system that provides secure identity verification through cryptographic hashes and off-chain biometric processing.

## Overview

This smart contract implements a decentralized identity verification system on the Stacks blockchain. It manages user identities, biometric templates, authorized devices, and verification events while ensuring privacy by storing only cryptographic hashes of biometric data, never the raw biometric information.

## Features

- **User Identity Management**: Create and manage user identity profiles
- **Biometric Template Storage**: Store cryptographic hashes of biometric templates
- **Device Authorization**: Manage authorized devices for verification
- **Verification Logging**: Comprehensive audit trail of verification attempts
- **Access Control**: Role-based permissions and security measures
- **Template Expiration**: Automatic expiration of biometric templates
- **User Suspension**: Administrative and self-suspension capabilities

## System Configuration

### Default Parameters

- **Verification Score Threshold**: 85 (minimum score for successful verification)
- **Maximum Verification Failures**: 5 attempts before restrictions
- **Template Validity Period**: 7,776,000 blocks (approximately 90 days)
- **Maximum Identifier Length**: 64 characters
- **Maximum Biometric Type Length**: 20 characters
- **Required Hash Length**: 32 bytes

### Error Codes

| Code | Description |
|------|-------------|
| 100  | Unauthorized Access |
| 101  | Insufficient Permissions |
| 102  | Identity Not Found |
| 103  | Duplicate Template Exists |
| 104  | Template Not Available |
| 106  | Verification Process Failed |
| 107  | Device Not Trusted |
| 109  | Template Expired |
| 111  | Identity Currently Suspended |
| 112  | Parameter Length Exceeded |
| 113  | Invalid Parameter Value |

## Data Structures

### User Identity Records
Stores user account information including:
- Account active status
- Registration block height
- Suspension end block
- Number of registered templates

### Biometric Template Storage
Contains template metadata:
- Template content hash (SHA-256)
- Biometric modality type (fingerprint, face, iris, etc.)
- Creation block height
- Template active status

### Authorized Device Registry
Manages authorized devices:
- Device credential hash
- Registration block height
- Device authorization status

### Verification Event Log
Audit trail of verification attempts:
- Verified user principal
- Verification block height
- Verification result
- Template and device identifiers used

## Public Functions

### Administrative Functions

#### `update-system-operational-status`
```clarity
(update-system-operational-status (new-active-status bool))
```
Updates the system's operational status. Only accessible by contract administrator.

#### `configure-verification-score-threshold`
```clarity
(configure-verification-score-threshold (new-threshold uint))
```
Configures the minimum verification score threshold (50-100 range).

### User Management Functions

#### `create-user-identity-profile`
```clarity
(create-user-identity-profile)
```
Creates a new user identity profile for the transaction sender.

#### `suspend-user-identity-access`
```clarity
(suspend-user-identity-access (target-user-principal principal) (suspension-block-duration uint))
```
Suspends a user's identity access for a specified duration. Can be called by the contract administrator or the user themselves.

### Biometric Template Management

#### `register-new-biometric-template`
```clarity
(register-new-biometric-template 
  (template-identifier (string-ascii 64))
  (template-content-hash (buff 32))
  (biometric-modality-type (string-ascii 20)))
```
Registers a new biometric template hash with the system.

#### `disable-biometric-template`
```clarity
(disable-biometric-template 
  (template-owner-principal principal)
  (template-identifier (string-ascii 64)))
```
Disables an existing biometric template.

### Device Management

#### `register-authorized-verification-device`
```clarity
(register-authorized-verification-device 
  (device-identifier (string-ascii 64))
  (device-credential-hash (buff 32)))
```
Registers a new authorized device for biometric verification.

### Verification Logging

#### `record-verification-attempt-result`
```clarity
(record-verification-attempt-result
  (verified-user-principal principal)
  (template-identifier (string-ascii 64))
  (device-identifier (string-ascii 64))
  (verification-result-success bool)
  (verification-proof-hash (buff 32)))
```
Records the result of a verification attempt in the audit log.

## Read-Only Functions

### Data Retrieval Functions

#### `get-user-identity-profile`
```clarity
(get-user-identity-profile (user-principal principal))
```
Returns the identity profile for a specified user.

#### `get-biometric-template-metadata`
```clarity
(get-biometric-template-metadata (user-principal principal) (template-identifier (string-ascii 64)))
```
Returns metadata for a specific biometric template.

#### `get-device-authorization-status`
```clarity
(get-device-authorization-status (user-principal principal) (device-identifier (string-ascii 64)))
```
Returns authorization status for a specific device.

#### `get-verification-log-entry`
```clarity
(get-verification-log-entry (event-sequence-id uint))
```
Returns a specific verification log entry.

#### `get-current-system-configuration`
```clarity
(get-current-system-configuration)
```
Returns current system configuration parameters.

#### `check-user-suspension-status`
```clarity
(check-user-suspension-status (user-principal principal))
```
Checks if a user is currently suspended.

## Security Features

### Access Control
- Contract administrator privileges for system management
- User-level permissions for self-management
- Device authorization requirements for verification

### Privacy Protection
- Only cryptographic hashes stored on-chain
- No raw biometric data stored in the contract
- Off-chain biometric processing recommended

### Audit Trail
- Comprehensive logging of all verification attempts
- Immutable record of system interactions
- Block height timestamps for all events

### Template Management
- Automatic expiration of biometric templates
- Manual template deactivation capabilities
- Duplicate prevention mechanisms

## Usage Examples

### Creating a User Profile
```clarity
(contract-call? .identity-contract create-user-identity-profile)
```

### Registering a Biometric Template
```clarity
(contract-call? .identity-contract register-new-biometric-template
  "fingerprint-template-001"
  0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
  "fingerprint")
```

### Recording a Verification Result
```clarity
(contract-call? .identity-contract record-verification-attempt-result
  'SP1234567890ABCDEF
  "fingerprint-template-001"
  "mobile-device-001"
  true
  0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890)
```

## Integration Guidelines

### Off-Chain Components
This contract is designed to work with off-chain biometric processing systems:

1. **Biometric Capture**: Devices capture biometric data locally
2. **Template Generation**: Off-chain processing creates biometric templates
3. **Hash Generation**: Templates are hashed before storage
4. **Verification Processing**: Matching occurs off-chain with results logged on-chain

### Recommended Architecture
```
[Biometric Device] -> [Off-chain Processor] -> [Smart Contract]
                         |
                   [Template Storage]
                   [Matching Engine]
```

## Deployment Considerations

### Network Requirements
- Stacks blockchain compatibility
- Sufficient block confirmation times for security
- Network fees for transaction processing

### Security Recommendations
- Implement secure key management for contract administration
- Use hardware security modules for biometric processing
- Regular security audits of the complete system
- Implement rate limiting for verification attempts

### Scalability Considerations
- Monitor gas usage for large-scale deployments
- Consider batch processing for multiple operations
- Plan for template rotation and cleanup procedures

## Limitations

- Maximum of 64 characters for identifiers
- 32-byte hash length requirement
- Block height dependent timing mechanisms
- Single contract administrator model