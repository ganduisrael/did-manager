;; DID Manager v1
;; A DID + Verifiable Credential registry with SIP-009 NFT credentials.
;; Clarity v2

;; Define NFT trait locally for development
(define-trait nft-trait
  ((transfer (uint principal principal (optional (string-utf8 34))) (response bool uint))
   (get-balance (principal) (response uint uint))
   (get-owner (uint) (response (optional principal) uint))
   (get-last-token-id () (response uint uint))
   (get-token-uri (uint) (response (optional (string-utf8 256)) uint))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Errors
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(define-constant ERR_UNAUTHORIZED           (err u100))
(define-constant ERR_NOT_ADMIN              (err u101))
(define-constant ERR_NOT_ALLOWED_ISSUER     (err u102))
(define-constant ERR_SCHEMA_NOT_FOUND       (err u103))
(define-constant ERR_CRED_NOT_FOUND         (err u104))
(define-constant ERR_ALREADY_REVOKED        (err u105))
(define-constant ERR_NOT_TOKEN_OWNER        (err u106))
(define-constant ERR_INVALID_EXPIRY         (err u107))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Data structures
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;; On-chain profile per principal
(define-map profiles
  { owner: principal }
  { name: (string-utf8 64), uri: (string-utf8 256) }
)

;; Credential Schemas (admin controls issuer allowlist)
(define-data-var last-schema-id uint u0)

(define-map schemas
  { id: uint }
  { name: (string-utf8 64), uri: (string-utf8 256), admin: principal }
)

;; Allowed issuers per schema
(define-map schema-issuers
  { id: uint, issuer: principal }
  { allowed: bool }
)

;; SIP-009 NFT representing an issued credential
(define-non-fungible-token credential-nft uint)

;; Incrementing token-id counter
(define-data-var next-token-id uint u1)

;; Token URIs (off-chain pointer for each credential token)
(define-map token-uris
  { token-id: uint }
  { uri: (string-utf8 256) }
)

;; Credential data payload
(define-map credentials
  { token-id: uint }
  {
    schema-id: uint,
    subject: principal,
    issuer: principal,
    hash: (buff 32),                ;; e.g., SHA-256 of the credential JSON
    issued-at: uint,                ;; block-height at issuance
    expires-at: (optional uint),    ;; optional block-height expiry
    revoked: bool
  }
)

;; Balances index (to satisfy SIP-009 get-balance efficiently)
(define-map balances
  { owner: principal }
  { count: uint }
)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Helpers
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(define-read-only (is-schema-admin (schema-id uint) (who principal))
  (let (
        (schema (map-get? schemas { id: schema-id }))
       )
    (match schema
      schema-data (is-eq who (get admin schema-data))
      false
    )
  )
)

(define-read-only (is-allowed-issuer? (schema-id uint) (who principal))
  (let (
        (row (map-get? schema-issuers { id: schema-id, issuer: who }))
       )
    (is-eq row (some { allowed: true }))
  )
)

(define-private (incr-balance (who principal))
  (let (
        (current (get count (default-to {count: u0} (map-get? balances { owner: who }))))
       )
    (map-set balances { owner: who } { count: (+ current u1) })
    true
  )
)

(define-private (decr-balance (who principal))
  (let (
        (current (get count (default-to {count: u0} (map-get? balances { owner: who }))))
       )
    (map-set balances { owner: who } { count: (if (> current u0) (- current u1) u0) })
    true
  )
)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Profile: register / update
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(define-public (register-profile (name (string-utf8 64)) (uri (string-utf8 256)))
  (begin
    (map-set profiles { owner: tx-sender } { name: name, uri: uri })
    (ok true)
  )
)

(define-read-only (get-profile (who principal))
  (ok (map-get? profiles { owner: who }))
)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Schema management
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;; Anyone can create a schema; creator becomes admin and is allowed issuer by default.
(define-public (create-schema (name (string-utf8 64)) (uri (string-utf8 256)))
  (let (
        (new-id (+ (var-get last-schema-id) u1))
       )
    (var-set last-schema-id new-id)
    (map-set schemas { id: new-id } { name: name, uri: uri, admin: tx-sender })
    (map-set schema-issuers { id: new-id, issuer: tx-sender } { allowed: true })
    (ok new-id)
  )
)

;; Only schema admin can manage issuers.
(define-public (allow-issuer (schema-id uint) (issuer principal))
  (begin
    (asserts! (is-schema-admin schema-id tx-sender) ERR_NOT_ADMIN)
    (map-set schema-issuers { id: schema-id, issuer: issuer } { allowed: true })
    (ok true)
  )
)

(define-public (revoke-issuer (schema-id uint) (issuer principal))
  (begin
    (asserts! (is-schema-admin schema-id tx-sender) ERR_NOT_ADMIN)
    (map-set schema-issuers { id: schema-id, issuer: issuer } { allowed: false })
    (ok true)
  )
)

(define-read-only (get-schema (schema-id uint))
  (ok (map-get? schemas { id: schema-id }))
)

(define-read-only (is-issuer-allowed (schema-id uint) (issuer principal))
  (is-allowed-issuer? schema-id issuer)
)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Credential issuance (NFT), revocation, verification
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;; Issue a credential NFT to 'subject' under 'schema-id'.
;; 'hash' is the 32-byte digest (e.g., sha256) of the credential JSON stored off-chain.
;; 'expires-at' is optional block-height when the credential expires.
;; 'token-uri' points to off-chain metadata (IPFS/HTTPS).
(define-public (issue-credential
  (schema-id uint)
  (subject principal)
  (hash (buff 32))
  (expires-at (optional uint))
  (token-uri (string-utf8 256))
)
  (begin
    ;; Ensure schema exists
    (asserts!
      (is-some (map-get? schemas { id: schema-id }))
      ERR_SCHEMA_NOT_FOUND
    )
    ;; Ensure tx-sender is an allowed issuer for this schema
    (asserts!
      (is-allowed-issuer? schema-id tx-sender)
      ERR_NOT_ALLOWED_ISSUER
    )
    ;; Validate expiry, if provided (must be in the future relative to current height)
    (asserts!
      (match expires-at
        exp-height (> exp-height burn-block-height)
        true)
      ERR_INVALID_EXPIRY
    )
    ;; Mint NFT
    (let (
          (tid (var-get next-token-id))
         )
      (try! (nft-mint? credential-nft tid subject))
      (map-set token-uris { token-id: tid } { uri: token-uri })
      (map-set credentials
        { token-id: tid }
        {
          schema-id: schema-id,
          subject: subject,
          issuer: tx-sender,
          hash: hash,
          issued-at: burn-block-height,
          expires-at: expires-at,
          revoked: false
        }
      )
      (incr-balance subject)
      (var-set next-token-id (+ tid u1))
      (ok tid)
    )
  )
)

;; Revoke a credential. Only the original issuer or the schema admin may revoke.
(define-public (revoke-credential (token-id uint))
  (let (
        (c (map-get? credentials { token-id: token-id }))
       )
    (match c
      cred
        (let (
              (schema-id (get schema-id cred))
              (schema (map-get? schemas { id: (get schema-id cred) }))
             )
          (match schema
            s
              (begin
                (asserts!
                  (or (is-eq tx-sender (get issuer cred))
                      (is-eq tx-sender (get admin s)))
                  ERR_UNAUTHORIZED
                )
                (asserts! (not (get revoked cred)) ERR_ALREADY_REVOKED)
                (map-set credentials { token-id: token-id } (merge cred { revoked: true }))
                (ok true)
              )
            ERR_SCHEMA_NOT_FOUND
          )
        )
      ERR_CRED_NOT_FOUND
    )
  )
)

;; Read-only verification: valid if (not revoked) AND (not expired) AND token currently owned by someone.
(define-read-only (verify-credential (token-id uint))
  (let (
        (c (map-get? credentials { token-id: token-id }))
        (owner-res (nft-get-owner? credential-nft token-id))
       )
    (match c
      cred
        (let (
              (not-revoked (not (get revoked cred)))
              (not-expired (match (get expires-at cred)
                            exp-height (> exp-height burn-block-height)
                            true))
              (owned (match owner-res some-owner true false))
             )
          (ok (and owned (and not-revoked not-expired))))
      (ok false))
  )
)

;; Expose credential details
(define-read-only (get-credential (token-id uint))
  (ok (map-get? credentials { token-id: token-id }))
)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; SIP-009 required functions
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


(define-public (transfer (token-id uint) (sender principal) (recipient principal) (memo (optional (string-utf8 34))))
  (begin
    ;; Only the current owner can call transfer
    (asserts! (is-eq sender tx-sender) ERR_UNAUTHORIZED)
    ;; Execute NFT transfer
    (try! (nft-transfer? credential-nft token-id sender recipient))
    ;; Update balances index
    (decr-balance sender)
    (incr-balance recipient)
    (ok true)
  )
)

(define-read-only (get-balance (who principal))
  (ok (get count (default-to {count: u0} (map-get? balances { owner: who }))))
)

(define-read-only (get-owner (token-id uint))
  (nft-get-owner? credential-nft token-id)
)

(define-read-only (get-last-token-id)
  (let ((next (var-get next-token-id)))
    ;; If next is u1, none minted yet; return u0
    (ok (if (> next u1) (- next u1) u0))
  )
)

(define-read-only (get-token-uri (token-id uint))
  (ok (match (map-get? token-uris { token-id: token-id })
       val (some (get uri val))
       none))
)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Convenience getters
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(define-read-only (is-revoked (token-id uint))
  (let ((c (map-get? credentials { token-id: token-id })))
    (ok (match c cred (get revoked cred) false))
  )
)

(define-read-only (get-schema-admin (schema-id uint))
  (let ((s (map-get? schemas { id: schema-id })))
    (ok (match s
        schema (some (get admin schema))
        none))
  )
)

(define-read-only (is-credential-expired (token-id uint))
  (let ((c (map-get? credentials { token-id: token-id })))
    (ok (match c
         cred (match (get expires-at cred)
                exp-height (> burn-block-height exp-height)
                false)
         false))
  )
)