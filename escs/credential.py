"""
credential.py

module to help manage a credential JSON-LD document
"""
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization as s11n

## Issuer
def issuer_from_credential(credential):
    return credential['obi:badge']['ocd:awardedBy']


## Signatures
def create_ld_signature(signature_bytes, public_key_url):
  """
  Parameters
    signautre: signature bytes object
  """
  b64signature = base64.urlsafe_b64encode(signature_bytes)
  return {
    "@type": "RsaSignature2018",
    "sec:creator": public_key_url,
    "sec:created": "2019-01-22T12:38:44Z",
    "sec:signatureValue": b64signature.decode('utf-8')
  }


def signature_bytes_from_ld_signature(ld_signature):
  """
  Parameters:
    ld_signatue: LinkedDataSignatures object containing a signatureValue
                 key representing a base64 encoded signature of the
                 document
  """
  b64signature = ld_signature['sec:signatureValue'].encode('utf-8')
  return base64.urlsafe_b64decode(b64signature)


def rsa_public_key_from_issuer(issuer):
  """Retrieves the public key from the credential."""
  public_key_pem = issuer['sec:publicKey']['sec:publicKeyPem']
  public_key = s11n.load_pem_public_key(public_key_pem.encode('utf-8'), default_backend())
  return public_key


