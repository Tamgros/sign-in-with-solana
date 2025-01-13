

from dataclasses import dataclass
from typing import List, Optional, Union
import re
from datetime import datetime
import base58
from solders.signature import Signature
from solders.pubkey import Pubkey
import sign_in_with_solana.types.models as models

#working off of the js library
# https://github.com/anza-xyz/wallet-standard/blob/b33d632b86227256c96be9d6df4813cb99a87282/packages/core/util/src/signIn.ts#L8



# Regular expressions for message parsing
DOMAIN = r'(?P<domain>[^\n]+?) wants you to sign in with your Solana account:\n'
ADDRESS = r'(?P<address>[^\n]+)(?:\n|$)'
STATEMENT = r'(?:\n(?P<statement>[\S\s]*?)(?:\n|$)??)'
URI = r'(?:\nURI: (?P<uri>[^\n]+))?'
VERSION = r'(?:\nVersion: (?P<version>[^\n]+))?'
CHAIN_ID = r'(?:\nChain ID: (?P<chainId>[^\n]+))?'
NONCE = r'(?:\nNonce: (?P<nonce>[^\n]+))?'
ISSUED_AT = r'(?:\nIssued At: (?P<issuedAt>[^\n]+))?'
EXPIRATION_TIME = r'(?:\nExpiration Time: (?P<expirationTime>[^\n]+))?'
NOT_BEFORE = r'(?:\nNot Before: (?P<notBefore>[^\n]+))?'
REQUEST_ID = r'(?:\nRequest ID: (?P<requestId>[^\n]+))?'
RESOURCES = r'(?:\nResources:(?P<resources>(?:\n- [^\n]+)*))?'
FIELDS = f"{URI}{VERSION}{CHAIN_ID}{NONCE}{ISSUED_AT}{EXPIRATION_TIME}{NOT_BEFORE}{REQUEST_ID}{RESOURCES}"
MESSAGE = re.compile(f"^{DOMAIN}{ADDRESS}{STATEMENT}{FIELDS}\n*$")

def create_sign_in_message_text(input: models.SolanaSignInInput) -> str:

    """Creates a formatted sign-in message text from input data."""
    # ${domain} wants you to sign in with your Solana account:
    # ${address}
    #
    # ${statement}
    #
    # URI: ${uri}
    # Version: ${version}
    # Chain ID: ${chain}
    # Nonce: ${nonce}
    # Issued At: ${issued-at}
    # Expiration Time: ${expiration-time}
    # Not Before: ${not-before}
    # Request ID: ${request-id}
    # Resources:
    # - ${resources[0]}
    # - ${resources[1]}
    # ...
    # - ${resources[n]}
    message = f"{input.domain} wants you to sign in with your Solana account:\n"
    message += f"{input.address}"

    if input.statement:
        message += f"\n\n{input.statement}"

    fields = []
    if input.uri:
        fields.append(f"URI: {input.uri}")
    if input.version:
        fields.append(f"Version: {input.version}")
    if input.chainId:
        fields.append(f"Chain ID: {input.chainId}")
    if input.nonce:
        fields.append(f"Nonce: {input.nonce}")
    if input.issuedAt:
        fields.append(f"Issued At: {input.issuedAt}")
    if input.expirationTime:
        fields.append(f"Expiration Time: {input.expirationTime}")
    if input.notBefore:
        fields.append(f"Not Before: {input.notBefore}")
    if input.requestId:
        fields.append(f"Request ID: {input.requestId}")
    if input.resources:
        fields.append("Resources:")
        for resource in input.resources:
            fields.append(f"- {resource}")

    if fields:
        message += f"\n\n{chr(10).join(fields)}"

    return message

def create_sign_in_message(input: models.SolanaSignInInput) -> bytes:
    """Creates a UTF-8 encoded message from input data."""
    text = create_sign_in_message_text(input)
    return text.encode('utf-8')

def parse_sign_in_message_text(text: str) -> Optional[models.SolanaSignInInput]:
    """Parses a sign-in message text into structured data."""
    match = MESSAGE.match(text)
    if not match:
        return None
    
    groups = match.groupdict()
    resources = groups.get('resources')
    if resources:
        resources = [r[2:] for r in resources.split('\n-')[1:]]
    
    return SolanaSignInInput(
        domain=groups['domain'],
        address=groups['address'],
        statement=groups.get('statement'),
        uri=groups.get('uri'),
        version=groups.get('version'),
        chainId=groups.get('chainId'),
        nonce=groups.get('nonce'),
        issuedAt=groups.get('issuedAt'),
        expirationTime=groups.get('expirationTime'),
        notBefore=groups.get('notBefore'),
        requestId=groups.get('requestId'),
        resources=resources
    )

def parse_sign_in_message(message: bytes) -> Optional[models.SolanaSignInInput]:
    """Parses a UTF-8 encoded message into structured data."""
    text = message.decode('utf-8')
    return parse_sign_in_message_text(text)

def verify_sign_in(input: models.SolanaSignInInput, output: models.SolanaSignInOutput) -> bool:
    """Verifies a sign-in message against input and output data."""
    try:
        message = create_sign_in_message(input)
        if not message:
            return False
            
        # Verify the signature
        return output.signature.verify(
            output.publicKey,
            output.signedMessage
        )
    except Exception as e:
        print(f"Verification error: {str(e)}")
        return False

# Helper function to compare arrays
def arrays_equal(a: List, b: List) -> bool:
    if len(a) != len(b):
        return False
    return all(x == y for x, y in zip(a, b))

