import base64
import copy
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
import functools as ft
import json
from pyld import jsonld
import sys


def create_key_pair(key_size=2048, backend_factory=default_backend):
  private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=key_size,
    backend=backend_factory())

  return private_key, private_key.public_key()


def get_context(opencreds_url=None):
  if opencreds_url is None:
    opencreds_url = "https://std.ncvet.gov.in/cred/opencreds#"

  return {
    "ocd": opencreds_url,
    "obi": "https://w3id.org/openbadges#",
    "schema": "http://schema.org/",
    "wid": "https://w3id.org/identity/v1",
  }


def create_credential():
  doc = {
    "@id": "https://www.example.com/certs/2018/9900001234.json",
    "@type": "obi:Assertion",
    "obi:recipient": {
      "@type": "email",
      "obi:hashed": "true",
      "obi:identity": "sha256$bdeffdadbd28657adcead3825fdb23875dab8e928ad8d68f6",
      "obi:salt": "bluewater",
      "obi:name": "Example Recipient Name",
    },
    "obi:badge": {
      "@id": "urn:uuid:ec58b28e-a6ab-49c2-a24d-ebefa02476cd",
      "@type": "obi:BadgeClass",
      "obi:name": "Certificate of Participation",
      "obi:description": "Content Marketing Course",
      "obi:issuer": {
        "@type": "obi:Profile",
        "@id": "tag:example.com,2009-11-28:#company.json",
        "obi:name": "Example Training Corp",
        "obi:image": "https://www.example.com/images/logo.png",
        "obi:email": "certificates@example.com",
      },
    },
    "obi:issuedOn": "2018-08-11T09:27:30.613UTC",
    "obi:narrative": "Issued for participating in Content Marketing Course in association with Partner Marketing Solutions",
    "obi:verification": {
      "@type": "ocd:LinkedDataSignatures"
    },
    "ocd:signatory": [{
      "@type": ["ocd:CompositeIdentity", "obi:Extension", "ocd:SignatoryExtension"],
      "ocd:components": [{
        "@type": ["obi:IdentityObject", "ocd:name"],
        "ocd:annotation": "FATHER",
        "obi:identity": "Example Father Name"
      }, {
        "@type": ["obi:IdentityObject", "ocd:photo"],
        "obi:identity": "data:image/jpeg;base64,<base64 jpg image>"
      }],
      "obi:name": "Example Signatory Name",
      "obi:image": "https://example.com/p/ceo/sign-image.jpg",
      "ocd:designation": "CEO, Example Training Corp",
    }, {
      "@type": ["ocd:IdentityObject", "oc:urn", "ob:Extension", "oc:SignatoryExtension"],
      "obi:name": "<Name of signatory>",
      "obi:image": "https://example2.com/edb/l:dir/mkt/sign-image.jpg",
      "obi:identity": "urn:in.gov.eci.voter:<Voter #>",
      "ocd:designation": "Director, Partner Marketing Solutions",
    }]
  }
  return jsonld.compact(doc, get_context())


def normalize_RsaSignature2018(credential):
  """The normalisation operation will produce a canonical
  representation of the credential according to the URDNA2015
  canonicalisation method"""
  return jsonld.normalize(credential, options={
        'algorithm': 'URDNA2015',
        'format': 'application/n-quads'
  })


def create_RsaSignature2018(credential, private_key):
  """Given a JSON-LD credential and a RSAPrivateKey, will
  return the signature of the credential according to the
  RsaSignature2018 signature suite specification"""
  normalized = normalize_RsaSignature2018(credential)
  return private_key.sign(data=normalized.encode('utf-8'),
                          padding=padding.PKCS1v15(),
                          algorithm=hashes.SHA256())


def verify_RsaSignature2018(credential, public_key, signature):
  """Given a JSON-LD credential and a RSAPublicKey, will
  verify the signature of the credential according to the
  RsaSignature2018 signature suite specification"""
  normalized = normalize_RsaSignature2018(credential)
  try:
    public_key.verify(signature, data=normalized.encode('utf-8'),
                      padding=padding.PKCS1v15(),
                      algorithm=hashes.SHA256())
    return True
  except InvalidSignature as e:
    return False


def create_ld_signature(signature):
  return {
    "@type": "RsaSignature2018",
    "wid:creator": "https://example.com/keys/1/sampleKey",
    "wid:created": "2019-01-22T12:38:44Z",
    "wid:signatureValue": signature
  }


if __name__ == '__main__':
  credential = create_credential()
  private_key, public_key = create_key_pair()

  signature = create_RsaSignature2018(credential, private_key)
  verified = verify_RsaSignature2018(credential, public_key, signature)
  assert verified == True
  print('Signature verified from bytes', file=sys.stderr)

  ld_signature = create_ld_signature(base64.urlsafe_b64encode(signature).decode('utf-8'))
  credential['ocd:signature'] = ld_signature
  print(json.dumps(credential, indent=2))

  stripped_credential = copy.deepcopy(credential)
  retrieved_signature = stripped_credential.pop('ocd:signature')
  signature_bytes = base64.urlsafe_b64decode(retrieved_signature['wid:signatureValue'].encode('utf-8'))
  verified_from_doc = verify_RsaSignature2018(stripped_credential, public_key, signature_bytes)
  assert verified_from_doc == True
  print('Signature verified from doc', file=sys.stderr)

