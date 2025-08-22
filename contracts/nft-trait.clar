;; NFT Trait Contract
(define-trait nft-trait
  (
    ;; Transfer an NFT from sender to recipient with an optional memo.
    ;; Must be called by sender.
    (transfer (uint principal principal (optional (string-utf8 34))) (response bool uint))
    ;; Get how many NFTs a principal currently owns.
    (get-balance (principal) (response uint uint))
    ;; Get the current owner of a token-id.
    (get-owner (uint) (response (optional principal) uint))
    ;; Get the last (highest) token-id that has been minted (or u0 if none).
    (get-last-token-id () (response uint uint))
    ;; Optional token URI for metadata
    (get-token-uri (uint) (response (optional (string-utf8 256)) uint))
  )
)
