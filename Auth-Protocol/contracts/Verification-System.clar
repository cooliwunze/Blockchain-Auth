;; Decentralized Identity Verification Gateway Smart Contract
;; A blockchain-based biometric identity management system that provides secure
;; identity verification through cryptographic hashes and off-chain biometric processing

;; Core system configuration parameters
(define-constant contract-owner tx-sender)
(define-constant default-verification-score-threshold u85)
(define-constant max-verification-failures-allowed u5)
(define-constant biometric-template-validity-period u7776000)
(define-constant max-identifier-length u64)
(define-constant max-biometric-type-length u20)
(define-constant required-hash-length u32)

;; System error codes
(define-constant ERR-UNAUTHORIZED-ACCESS (err u100))
(define-constant ERR-INSUFFICIENT-PERMISSIONS (err u101))
(define-constant ERR-IDENTITY-NOT-FOUND (err u102))
(define-constant ERR-DUPLICATE-TEMPLATE-EXISTS (err u103))
(define-constant ERR-TEMPLATE-NOT-AVAILABLE (err u104))
(define-constant ERR-VERIFICATION-PROCESS-FAILED (err u106))
(define-constant ERR-DEVICE-NOT-TRUSTED (err u107))
(define-constant ERR-TEMPLATE-EXPIRED (err u109))
(define-constant ERR-IDENTITY-CURRENTLY-SUSPENDED (err u111))
(define-constant ERR-PARAMETER-LENGTH-EXCEEDED (err u112))
(define-constant ERR-INVALID-PARAMETER-VALUE (err u113))

;; Global system state variables
(define-data-var system-active-status bool true)
(define-data-var minimum-verification-score uint default-verification-score-threshold)
(define-data-var maximum-failure-threshold uint max-verification-failures-allowed)
(define-data-var template-expiry-duration uint biometric-template-validity-period)

;; Primary data storage structures

;; User identity records with account status and metadata
(define-map user-identity-records
  { user-principal: principal }
  {
    account-is-active: bool,
    registration-block-height: uint,
    suspension-end-block: uint,
    registered-template-count: uint
  }
)

;; Biometric template metadata storage (hashes only, no raw biometric data)
(define-map biometric-template-storage
  { user-principal: principal, template-identifier: (string-ascii 64) }
  {
    template-content-hash: (buff 32),
    biometric-modality-type: (string-ascii 20),
    creation-block-height: uint,
    template-is-active: bool
  }
)

;; Authorized device registry for secure access control
(define-map authorized-device-registry
  { user-principal: principal, device-identifier: (string-ascii 64) }
  {
    device-credential-hash: (buff 32),
    registration-block-height: uint,
    device-is-authorized: bool
  }
)

;; Verification event logging for audit trails
(define-map verification-event-log
  { event-sequence-id: uint }
  {
    verified-user-principal: principal,
    verification-block-height: uint,
    verification-result-success: bool,
    used-template-identifier: (string-ascii 64),
    used-device-identifier: (string-ascii 64)
  }
)

(define-data-var next-log-entry-id uint u1)

;; Helper functions for access control and validation

(define-private (is-contract-administrator)
  (is-eq tx-sender contract-owner)
)

(define-private (check-user-account-active (user-principal principal))
  (match (map-get? user-identity-records { user-principal: user-principal })
    user-record (get account-is-active user-record)
    false
  )
)

(define-private (check-user-suspension-active (user-principal principal))
  (match (map-get? user-identity-records { user-principal: user-principal })
    user-record (> (get suspension-end-block user-record) burn-block-height)
    false
  )
)

(define-private (validate-string-parameter-length (string-param (string-ascii 64)) (max-length uint))
  (<= (len string-param) max-length)
)

(define-private (validate-biometric-type-parameter (biometric-type (string-ascii 20)) (max-length uint))
  (and 
    (<= (len biometric-type) max-length)
    (> (len biometric-type) u0)
  )
)

(define-private (validate-hash-buffer-length (hash-buffer (buff 32)) (expected-length uint))
  (is-eq (len hash-buffer) expected-length)
)

(define-private (check-template-expiration-status (template-data { template-content-hash: (buff 32), biometric-modality-type: (string-ascii 20), creation-block-height: uint, template-is-active: bool }))
  (let (
    (expiration-block-height (+ (get creation-block-height template-data) (var-get template-expiry-duration)))
  )
    (> burn-block-height expiration-block-height)
  )
)

;; Administrative functions for system management

(define-public (update-system-operational-status (new-active-status bool))
  (begin
    (asserts! (is-contract-administrator) ERR-UNAUTHORIZED-ACCESS)
    (var-set system-active-status new-active-status)
    (ok true)
  )
)

(define-public (configure-verification-score-threshold (new-threshold uint))
  (begin
    (asserts! (is-contract-administrator) ERR-UNAUTHORIZED-ACCESS)
    (asserts! (and (>= new-threshold u50) (<= new-threshold u100)) ERR-INVALID-PARAMETER-VALUE)
    (var-set minimum-verification-score new-threshold)
    (ok true)
  )
)

;; User identity management functions

(define-public (create-user-identity-profile)
  (let ((user-principal-address tx-sender))
    (asserts! (var-get system-active-status) ERR-UNAUTHORIZED-ACCESS)
    (asserts! (is-none (map-get? user-identity-records { user-principal: user-principal-address })) ERR-DUPLICATE-TEMPLATE-EXISTS)
    (map-set user-identity-records
      { user-principal: user-principal-address }
      {
        account-is-active: true,
        registration-block-height: block-height,
        suspension-end-block: u0,
        registered-template-count: u0
      }
    )
    (ok true)
  )
)

(define-public (suspend-user-identity-access (target-user-principal principal) (suspension-block-duration uint))
  (begin
    (asserts! (or (is-contract-administrator) (is-eq tx-sender target-user-principal)) ERR-INSUFFICIENT-PERMISSIONS)
    (asserts! (is-some (map-get? user-identity-records { user-principal: target-user-principal })) ERR-IDENTITY-NOT-FOUND)
    (let ((existing-user-record (unwrap-panic (map-get? user-identity-records { user-principal: target-user-principal }))))
      (map-set user-identity-records 
        { user-principal: target-user-principal }
        (merge existing-user-record { 
          suspension-end-block: (+ burn-block-height suspension-block-duration)
        })
      )
    )
    (ok true)
  )
)

;; Biometric template management functions

(define-public (register-new-biometric-template 
  (template-identifier (string-ascii 64))
  (template-content-hash (buff 32))
  (biometric-modality-type (string-ascii 20))
)
  (let ((template-owner-principal tx-sender))
    (asserts! (var-get system-active-status) ERR-UNAUTHORIZED-ACCESS)
    (asserts! (check-user-account-active template-owner-principal) ERR-IDENTITY-NOT-FOUND)
    (asserts! (validate-string-parameter-length template-identifier max-identifier-length) ERR-PARAMETER-LENGTH-EXCEEDED)
    (asserts! (validate-biometric-type-parameter biometric-modality-type max-biometric-type-length) ERR-PARAMETER-LENGTH-EXCEEDED)
    (asserts! (validate-hash-buffer-length template-content-hash required-hash-length) ERR-PARAMETER-LENGTH-EXCEEDED)
    (asserts! (is-none (map-get? biometric-template-storage 
                        { user-principal: template-owner-principal, template-identifier: template-identifier })) 
              ERR-DUPLICATE-TEMPLATE-EXISTS)
    
    (let ((owner-identity-record (unwrap-panic (map-get? user-identity-records { user-principal: template-owner-principal }))))
      (map-set biometric-template-storage
        { user-principal: template-owner-principal, template-identifier: template-identifier }
        {
          template-content-hash: template-content-hash,
          biometric-modality-type: biometric-modality-type,
          creation-block-height: burn-block-height,
          template-is-active: true
        }
      )
      (map-set user-identity-records 
        { user-principal: template-owner-principal }
        (merge owner-identity-record {
          registered-template-count: (+ (get registered-template-count owner-identity-record) u1)
        })
      )
    )
    (ok true)
  )
)

(define-public (disable-biometric-template 
  (template-owner-principal principal)
  (template-identifier (string-ascii 64))
)
  (begin
    (asserts! (or (is-contract-administrator) (is-eq tx-sender template-owner-principal)) ERR-INSUFFICIENT-PERMISSIONS)
    (asserts! (validate-string-parameter-length template-identifier max-identifier-length) ERR-PARAMETER-LENGTH-EXCEEDED)
    (asserts! (is-some (map-get? biometric-template-storage 
                        { user-principal: template-owner-principal, template-identifier: template-identifier })) 
              ERR-TEMPLATE-NOT-AVAILABLE)
    
    (let ((target-template-record (unwrap-panic (map-get? biometric-template-storage 
                                                  { user-principal: template-owner-principal, template-identifier: template-identifier }))))
      (map-set biometric-template-storage 
        { user-principal: template-owner-principal, template-identifier: template-identifier }
        (merge target-template-record { template-is-active: false })
      )
    )
    (ok true)
  )
)

;; Device authorization management functions

(define-public (register-authorized-verification-device 
  (device-identifier (string-ascii 64))
  (device-credential-hash (buff 32))
)
  (let ((device-owner-principal tx-sender))
    (asserts! (var-get system-active-status) ERR-UNAUTHORIZED-ACCESS)
    (asserts! (check-user-account-active device-owner-principal) ERR-IDENTITY-NOT-FOUND)
    (asserts! (validate-string-parameter-length device-identifier max-identifier-length) ERR-PARAMETER-LENGTH-EXCEEDED)
    (asserts! (validate-hash-buffer-length device-credential-hash required-hash-length) ERR-PARAMETER-LENGTH-EXCEEDED)
    (asserts! (is-none (map-get? authorized-device-registry 
                        { user-principal: device-owner-principal, device-identifier: device-identifier })) 
              ERR-DUPLICATE-TEMPLATE-EXISTS)
    
    (map-set authorized-device-registry
      { user-principal: device-owner-principal, device-identifier: device-identifier }
      {
        device-credential-hash: device-credential-hash,
        registration-block-height: burn-block-height,
        device-is-authorized: true
      }
    )
    (ok true)
  )
)

;; Verification result logging function

(define-public (record-verification-attempt-result
  (verified-user-principal principal)
  (template-identifier (string-ascii 64))
  (device-identifier (string-ascii 64))
  (verification-result-success bool)
  (verification-proof-hash (buff 32))
)
  (let ((current-log-id (var-get next-log-entry-id)))
    (asserts! (var-get system-active-status) ERR-UNAUTHORIZED-ACCESS)
    (asserts! (check-user-account-active verified-user-principal) ERR-IDENTITY-NOT-FOUND)
    (asserts! (not (check-user-suspension-active verified-user-principal)) ERR-IDENTITY-CURRENTLY-SUSPENDED)
    (asserts! (validate-string-parameter-length template-identifier max-identifier-length) ERR-PARAMETER-LENGTH-EXCEEDED)
    (asserts! (validate-string-parameter-length device-identifier max-identifier-length) ERR-PARAMETER-LENGTH-EXCEEDED)
    (asserts! (validate-hash-buffer-length verification-proof-hash required-hash-length) ERR-PARAMETER-LENGTH-EXCEEDED)
    
    (match (map-get? biometric-template-storage 
             { user-principal: verified-user-principal, template-identifier: template-identifier })
      template-record
      (begin
        (asserts! (get template-is-active template-record) ERR-TEMPLATE-NOT-AVAILABLE)
        (asserts! (not (check-template-expiration-status template-record)) ERR-TEMPLATE-EXPIRED)
        
        (match (map-get? authorized-device-registry 
                 { user-principal: verified-user-principal, device-identifier: device-identifier })
          device-record
          (begin
            (asserts! (get device-is-authorized device-record) ERR-DEVICE-NOT-TRUSTED)
            
            (map-set verification-event-log
              { event-sequence-id: current-log-id }
              {
                verified-user-principal: verified-user-principal,
                verification-block-height: burn-block-height,
                verification-result-success: verification-result-success,
                used-template-identifier: template-identifier,
                used-device-identifier: device-identifier
              }
            )
            (var-set next-log-entry-id (+ current-log-id u1))
            (ok current-log-id)
          )
          ERR-DEVICE-NOT-TRUSTED
        )
      )
      ERR-TEMPLATE-NOT-AVAILABLE
    )
  )
)

;; Public read-only functions for data retrieval

(define-read-only (get-user-identity-profile (user-principal principal))
  (map-get? user-identity-records { user-principal: user-principal })
)

(define-read-only (get-biometric-template-metadata (user-principal principal) (template-identifier (string-ascii 64)))
  (map-get? biometric-template-storage { user-principal: user-principal, template-identifier: template-identifier })
)

(define-read-only (get-device-authorization-status (user-principal principal) (device-identifier (string-ascii 64)))
  (map-get? authorized-device-registry { user-principal: user-principal, device-identifier: device-identifier })
)

(define-read-only (get-verification-log-entry (event-sequence-id uint))
  (map-get? verification-event-log { event-sequence-id: event-sequence-id })
)

(define-read-only (get-current-system-configuration)
  {
    system-active-status: (var-get system-active-status),
    minimum-verification-score: (var-get minimum-verification-score),
    maximum-failure-threshold: (var-get maximum-failure-threshold),
    template-expiry-duration: (var-get template-expiry-duration)
  }
)

(define-read-only (check-user-suspension-status (user-principal principal))
  (check-user-suspension-active user-principal)
)