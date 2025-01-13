# sign-in-with-solana
## **Summary**

Sign in with Solana is a process for authenticating your Solana public key. The main aspects are

- Standard message format
    - This proposal does not reinvent the wheel, the emulates EIP-4361 and several existing sign in with Solana implementations that already exist within the Solana ecosystem.
    - Note: to avoid contention and overloading this proposal, the exact specification ChainID that is adopted by the ecosystem is not in scope for this SIMD. We merely include it’s existence and data type as an optional field
- Process for signing the message and communication to the user.

## **Motivation**

Creating accounts have historically been a friction point for new users often with a tradeoff of simplicity and security. It also is an error surface for users when choosing between an easy to remember password and the complexity of unique and secure passwords. This has given rise to methods like single sign on. This puts a lot of power into that provider that can control your account, information and because users are sticky, apps have a lot of UX lock-in that is now dictated by the SSO provider.

Signing with a private key offers a lot of benefits, but it does introduce some risks, namely it requires a signature by the user. This SIMD will provide a standard flow so wallets can provide a consistent way for users to know it’s reliable. 

Included in this standard

- A recommended consistent flow and message format
- The consistent format includes domain, nonce, and other information that enables wallets to alert users of potentially harmful message signing.

**New Terminology**

Spoiler, I ganked this almost directly from EIP-4361 and Phantom’s SIWS 

Input Fields

- `domain`: Optional EIP-4361 domain requesting the sign-in. If not provided, the wallet must determine the domain to include in the message.
- `address`: Optional Solana address performing the sign-in. The address is case-sensitive. If not provided, the wallet must determine the Address to include in the message.
- `statement`: Optional EIP-4361 Statement. The statement is a human readable string and should not have new-line characters (`\n`). If not provided, the wallet must not include Statement in the message.
- `uri`: Optional EIP-4361 URI. The URL that is requesting the sign-in. If not provided, the wallet must not include URI in the message.
- `version`: Optional EIP-4361 version. If not provided, the wallet must not include Version in the message.
- `chainId`: Optional EIP-4361 Chain ID. String
    - This proposal is simply for the existence of the optional field and that it be of type String. That will allow for it to be flexible to both human readable names, sting based numbers or genesis hashes.
    - If not provided, the wallet must not include Chain ID in the message.
- `nonce`: Optional EIP-4361 Nonce. It should be an alphanumeric string containing a minimum of 8 characters. If not provided, the wallet must not include Nonce in the message.
- `issuedAt`: Optional ISO 8601 datetime string. This represents the time at which the sign-in request was issued to the wallet. Note: For Phantom, issuedAt has a threshold and it should be within +- 10 minutes from the timestamp at which verification is taking place. If not provided, the wallet must not include Issued At in the message.
- `expirationTime`: Optional ISO 8601 datetime string. This represents the time at which the sign-in request should expire. If not provided, the wallet must not include Expiration Time in the message.
- `notBefore`: Optional ISO 8601 datetime string. This represents the time at which the sign-in request becomes valid. If not provided, the wallet must not include Not Before in the message.
- `requestId`: Optional EIP-4361 Request ID. In addition to using `nonce` to avoid replay attacks, dapps can also choose to include a unique signature in the `requestId` . Once the wallet returns the signed message, dapps can then verify this signature against the state to add an additional, strong layer of security. If not provided, the wallet must not include Request ID in the message.
- `resources`: Optional EIP-4361 Resources. Usually a list of references in the form of URIs that the dapp wants the user to be aware of. These URIs should be separated by `\n-`, ie, URIs in new lines starting with the character . If not provided, the wallet must not include Resources in the message.

Output fields

- `account` [`WalletAccount`]: Account that was signed in. The address of the account may be different from the provided input Address.
- `signedMessage` [`Uint8Array`]: Message bytes that were signed. The wallet is responsible for constructing this message using the `signInInput`.
- `signature` [`Uint8Array`]: Message signature produced. If the signature type is not provided, the signature must be Ed25519.
- `signatureType` [`"ed25519"`]: Optional type of the message signature produced. If not provided, the signature must be Ed25519.

## **Detailed Design**

The Sign In With Solana message constructed by the wallet using `signInInput` should follow the `sign-in-with-solana` Augment Backus–Naur Form expression:

```jsx
sign-in-with-solana =
  [ scheme "://" ] message-domain %s" wants you to sign in with your Solana account:" LF
  message-address
  [ LF LF message-statement ]
  [ LF advanced-fields ]

advanced-fields =
  [ LF %s"URI: " message-uri ]
  [ LF %s"Version: " message-version ]
  [ LF %s"Chain ID: " message-chain-id ]
  [ LF %s"Nonce: " message-nonce ]
  [ LF %s"Issued At: " message-issued-at ]
  [ LF %s"Expiration Time: " message-expiration-time ]
  [ LF %s"Not Before: " message-not-before ]
  [ LF %s"Request ID: " message-request-id ]
  [ LF %s"Resources:" message-resources ]

scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
    ; See RFC 3986 for the fully contextualized
    ; definition of "scheme".
message-domain          = authority
message-address         = 32*44( %x31-39 / %x41-48 / %x4A-4E / %x50-5A / %x61-6B / %x6D-7A )
message-statement       = 1*( reserved / unreserved / " " )
message-uri             = URI
message-version         = "1"
message-chain-id        = %s"mainnet" / %s"testnet" / %s"devnet" / %s"localnet" / %s"solana:mainnet" / %s"solana:testnet" / %s"solana:devnet"
message-nonce           = 8*( ALPHA / DIGIT )
message-issued-at       = date-time
message-expiration-time = date-time
message-not-before      = date-time
message-request-id      = *pchar
message-resources       = *( LF "- " URI )
```

This specification defines the following SIWS Message fields that can be parsed from a SIWE Message by following the rules in [ABNF Message Format](https://www.notion.so/Sign-in-with-Solana-14ad36dad52d80368c1fd920b37ae085?pvs=21):~~

- `~~scheme` OPTIONAL. The URI scheme of the origin of the request. Its value MUST be an RFC 3986 URI scheme.~~
- `~~domain` REQUIRED. The domain that is requesting the signing. Its value MUST be an RFC 3986 authority. The authority includes an OPTIONAL port. If the port is not specified, the default port for the provided `scheme` is assumed (e.g., 443 for HTTPS). If `scheme` is not specified, HTTPS is assumed by default.~~
- `~~address` REQUIRED. The Ethereum address performing the signing. Its value SHOULD be conformant to mixed-case checksum address encoding specified in [ERC-55](https://eips.ethereum.org/EIPS/eip-55) where applicable.~~
- `~~statement` OPTIONAL. A human-readable ASCII assertion that the user will sign which MUST NOT include `'\n'` (the byte `0x0a`).~~
- `~~uri` REQUIRED. An RFC 3986 URI referring to the resource that is the subject of the signing (as in the *subject of a claim*).~~
- `~~version` REQUIRED. The current version of the SIWE Message, which MUST be `1` for this specification.~~
- `~~chain-id` Optional. String.~~
- `~~nonce` REQUIRED. A random string typically chosen by the relying party and used to prevent replay attacks, at least 8 alphanumeric characters.~~
- `~~issued-at` REQUIRED. The time when the message was generated, typically the current time. Its value MUST be an ISO 8601 datetime string.~~
- `~~expiration-time` OPTIONAL. The time when the signed authentication message is no longer valid. Its value MUST be an ISO 8601 datetime string.~~
- `~~not-before` OPTIONAL. The time when the signed authentication message will become valid. Its value MUST be an ISO 8601 datetime string.~~
- `~~request-id` OPTIONAL. A system-specific identifier that MAY be used to uniquely refer to the sign-in request.~~
- `~~resources` OPTIONAL. A list of information or references to information the user wishes to have resolved as part of authentication by the relying party. Every resource MUST be an RFC 3986 URI separated by `"\n- "` where `\n` is the byte `0x0a`.~~

Informal foramat

```
${scheme}:// ${domain} wants you to sign in with your Solana account:
${address}

${statement}

URI: ${uri}
Version: ${version}
Chain ID: ${chain-id}
Nonce: ${nonce}
Issued At: ${issued-at}
Expiration Time: ${expiration-time}
Not Before: ${not-before}
Request ID: ${request-id}
Resources:
- ${resources[0]}
- ${resources[1]}
...
- ${resources[n]}
```

Signing and verifying

**Alternatives Considered**

Honestly there aren’t too many variants that I’m aware of that warrant serious consideration. The point of this initial doc is to field any recommendations.

**Impact**

The goal is to make it easy for apps and wallets to authenticate with Solana addresses. Instead of Apps needing to do complex login services, they are able to remember users without requiring them to store sensitive information

## **Security Considerations**

**Key management**

- Sign-In with Solana gives users control through their keys. This is additional responsibility that mainstream users may not be accustomed to accepting, and key management is a hard problem especially for individuals. For example, there is no "forgot password" button as centralized identity providers commonly implement.
- Early adopters of this specification are likely to be already adept at key management, so this consideration becomes more relevant with mainstream adoption.

**Preventing replay attacks**

- A `nonce` should be selected per session initiation with enough entropy to prevent replay attacks, a man-in-the-middle attack in which an attacker is able to capture the user's signature and resend it to establish a new session for themselves.
- Implementers MAY consider using privacy-preserving yet widely-available `nonce` values, such as one derived from a recent block hash or a recent Unix timestamp.

**Verification of domain binding**

- Wallets MUST check that the `domain` matches the the actual signing request source.
- This value SHOULD be checked against a trusted data source such as the browser window or over another protocol.

**Channel security**

- For web-based applications, all communications SHOULD use HTTPS to prevent man-in-the-middle attacks on the message signing.
- When using protocols other than HTTPS, all communications SHOULD be protected with proper techniques to maintain confidentiality, data integrity, and sender/receiver authenticity.  

<br>
<br>
<br>
  
## **TODO:**  

Add sign-in input generation (front end)

Add sign-in out put verification (backend)
