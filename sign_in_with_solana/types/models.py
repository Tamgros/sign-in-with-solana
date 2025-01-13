from dataclasses import dataclass
from typing import List, Optional
from solders.signature import Signature
from solders.pubkey import Pubkey

@dataclass
class SolanaSignInInput:
    domain: str
    address: str
    statement: Optional[str] = None
    uri: Optional[str] = None
    version: Optional[str] = None
    chainId: Optional[str] = None
    nonce: Optional[str] = None
    issuedAt: Optional[str] = None
    expirationTime: Optional[str] = None
    notBefore: Optional[str] = None
    requestId: Optional[str] = None
    resources: Optional[List[str]] = None

@dataclass
class SolanaSignInOutput:
    signedMessage: bytes
    signature: Signature
    publicKey: Pubkey