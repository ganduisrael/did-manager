;; SIP009 NFT Trait
(define-trait nft-trait
  ((transfer (uint principal principal (optional (string-utf8 34))) (response bool uint))
   (get-balance (principal) (response uint uint))
   (get-owner (uint) (response (optional principal) uint))
   (get-last-token-id () (response uint uint))
   (get-token-uri (uint) (response (optional (string-utf8 256)) uint))))
