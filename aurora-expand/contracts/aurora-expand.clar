;; Aurora Expand - Privacy-Preserving Identity Verification Platform
;; Simplified Stacks Clarity Smart Contract

;; Constants
(define-constant CONTRACT_OWNER tx-sender)
(define-constant ERR_UNAUTHORIZED (err u100))
(define-constant ERR_NOT_FOUND (err u101))
(define-constant ERR_ALREADY_EXISTS (err u102))
(define-constant ERR_EXPIRED (err u103))
(define-constant ERR_INVALID_ISSUER (err u104))

;; Data Variables
(define-data-var next-credential-id uint u1)
(define-data-var decay-rate uint u10) ;; Decay rate percentage per year

;; Data Maps
(define-map credentials
  uint
  {
    issuer: principal,
    holder: principal,
    credential-type: (string-ascii 64),
    issued-at: uint,
    expires-at: uint,
    credential-hash: (buff 32),
    is-active: bool
  }
)

(define-map verified-issuers
  principal
  {
    name: (string-ascii 64),
    trust-level: uint,
    verified-at: uint,
    is-active: bool
  }
)

(define-map user-credentials
  principal
  (list 50 uint)
)

(define-map credential-proofs
  {credential-id: uint, context: (string-ascii 32)}
  {
    proof-hash: (buff 32),
    verified-at: uint,
    is-valid: bool
  }
)

;; Public Functions

;; Register a verified issuer (only contract owner)
(define-public (register-issuer (issuer principal) (name (string-ascii 64)) (trust-level uint))
  (begin
    (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_UNAUTHORIZED)
    (asserts! (is-none (map-get? verified-issuers issuer)) ERR_ALREADY_EXISTS)
    (map-set verified-issuers issuer {
      name: name,
      trust-level: trust-level,
      verified-at: block-height,
      is-active: true
    })
    (ok true)
  )
)

;; Issue a new credential
(define-public (issue-credential 
  (holder principal) 
  (credential-type (string-ascii 64))
  (expires-at uint)
  (credential-hash (buff 32))
)
  (let
    (
      (credential-id (var-get next-credential-id))
      (issuer-info (map-get? verified-issuers tx-sender))
    )
    (asserts! (is-some issuer-info) ERR_INVALID_ISSUER)
    (asserts! (get is-active (unwrap-panic issuer-info)) ERR_INVALID_ISSUER)
    (asserts! (> expires-at block-height) ERR_EXPIRED)
    
    ;; Create the credential
    (map-set credentials credential-id {
      issuer: tx-sender,
      holder: holder,
      credential-type: credential-type,
      issued-at: block-height,
      expires-at: expires-at,
      credential-hash: credential-hash,
      is-active: true
    })
    
    ;; Update user's credential list
    (let
      (
        (current-credentials (default-to (list) (map-get? user-credentials holder)))
      )
      (map-set user-credentials holder 
        (unwrap-panic (as-max-len? (append current-credentials credential-id) u50))
      )
    )
    
    ;; Increment credential ID counter
    (var-set next-credential-id (+ credential-id u1))
    (ok credential-id)
  )
)

;; Verify a credential with zero-knowledge proof
(define-public (verify-credential 
  (credential-id uint) 
  (context (string-ascii 32))
  (proof-hash (buff 32))
)
  (let
    (
      (credential (map-get? credentials credential-id))
    )
    (asserts! (is-some credential) ERR_NOT_FOUND)
    (let
      (
        (cred-data (unwrap-panic credential))
      )
      (asserts! (get is-active cred-data) ERR_EXPIRED)
      (asserts! (> (get expires-at cred-data) block-height) ERR_EXPIRED)
      
      ;; Store the proof verification
      (map-set credential-proofs {credential-id: credential-id, context: context} {
        proof-hash: proof-hash,
        verified-at: block-height,
        is-valid: true
      })
      
      (ok true)
    )
  )
)

;; Revoke a credential (issuer or holder can revoke)
(define-public (revoke-credential (credential-id uint))
  (let
    (
      (credential (map-get? credentials credential-id))
    )
    (asserts! (is-some credential) ERR_NOT_FOUND)
    (let
      (
        (cred-data (unwrap-panic credential))
      )
      (asserts! 
        (or 
          (is-eq tx-sender (get issuer cred-data))
          (is-eq tx-sender (get holder cred-data))
        ) 
        ERR_UNAUTHORIZED
      )
      
      (map-set credentials credential-id 
        (merge cred-data {is-active: false})
      )
      (ok true)
    )
  )
)

;; Update decay rate (contract owner only)
(define-public (update-decay-rate (new-rate uint))
  (begin
    (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_UNAUTHORIZED)
    (var-set decay-rate new-rate)
    (ok true)
  )
)

;; Read-only Functions

;; Get credential details
(define-read-only (get-credential (credential-id uint))
  (map-get? credentials credential-id)
)

;; Get user's credentials
(define-read-only (get-user-credentials (user principal))
  (map-get? user-credentials user)
)

;; Get issuer information
(define-read-only (get-issuer-info (issuer principal))
  (map-get? verified-issuers issuer)
)

;; Check if credential is valid (considering decay)
(define-read-only (is-credential-valid (credential-id uint))
  (let
    (
      (credential (map-get? credentials credential-id))
    )
    (match credential
      cred-data
        (and
          (get is-active cred-data)
          (> (get expires-at cred-data) block-height)
          (calculate-credibility-score credential-id)
        )
      false
    )
  )
)

;; Calculate credibility score with temporal decay
(define-read-only (calculate-credibility-score (credential-id uint))
  (let
    (
      (credential (map-get? credentials credential-id))
    )
    (match credential
      cred-data
        (let
          (
            (age (- block-height (get issued-at cred-data)))
            (decay (var-get decay-rate))
            (issuer-trust (default-to u50 
              (get trust-level (map-get? verified-issuers (get issuer cred-data)))
            ))
          )
          ;; Simple credibility calculation: base trust level reduced by age-based decay
          (> (- issuer-trust (/ (* age decay) u100)) u0)
        )
      false
    )
  )
)

;; Get proof verification status
(define-read-only (get-proof-verification (credential-id uint) (context (string-ascii 32)))
  (map-get? credential-proofs {credential-id: credential-id, context: context})
)

;; Get next credential ID
(define-read-only (get-next-credential-id)
  (var-get next-credential-id)
)

;; Get current decay rate
(define-read-only (get-decay-rate)
  (var-get decay-rate)
)