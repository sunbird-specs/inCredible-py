"""
credential.py

module to help manage a credential JSON-LD document
"""
import base64
import datetime
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization as s11n
import json
from pyld import jsonld
from skillcreds import vocabs as voc

# Vocabulary prefixes
COMPACT_CONTEXT = dict((vocab.PREFIX, vocab.IRI) for vocab in [voc.ob, voc.scd, voc.sec, voc.schema])


# Credentials
def load_credential(filename):
  """Reads a credential document from filename and returns the compact
  JSON-LD representation of the credential."""
  with open(filename, 'r') as f:
    doc = json.load(f)
  return compact_credential(doc)


def compact_credential(doc):
  """Converts a JSON-LD credential into its compact representation."""
  doc_context = doc.pop('@context', {})
  jsonld.set_document_loader(jsonld.requests_document_loader(timeout=5))
  credential = jsonld.compact(doc, COMPACT_CONTEXT, options={'expandContext': doc_context})
  return credential


## Issuer
def issuer_from_credential(credential):
  """Extracts the issuer from a credential."""
  return credential[voc.ob.BADGE][voc.ob.ISSUER]


def set_issuer_public_key(credential, issuer_public_key, issuer_key_id):
  issuer = issuer_from_credential(credential)
  issuer[voc.sec.PUBLIC_KEY] = create_cryptographic_key(issuer_public_key,
                                                        issuer_key_id,
                                                        owner=issuer['@id'])


## Keys
def create_cryptographic_key(public_key, key_url, owner):
  """Create a LD CryptographicKey object from a RSA public key, with id=key_url, owner=owner."""
  public_key_bytes = public_key.public_bytes(encoding=s11n.Encoding.PEM,
                                             format=s11n.PublicFormat.SubjectPublicKeyInfo)
  return {
    "@id": key_url,
    "@type": voc.sec.KEY,
    voc.sec.OWNER: owner,
    voc.sec.PUBLIC_KEY_PEM: public_key_bytes.decode('utf-8')
  }


def public_key_from_issuer(issuer):
  """Retrieves the public key from the credential and also converts to
  rsa_public_key. """
  public_key = issuer[voc.sec.PUBLIC_KEY]
  public_key_pem = public_key[voc.sec.PUBLIC_KEY_PEM]
  public_key_bytes = public_key_pem.encode('utf8')
  rsa_public_key = s11n.load_pem_public_key(public_key_bytes, default_backend())
  return public_key, rsa_public_key


def create_ld_signature(signature_bytes, creator, created, sig_type=None):
  """
  Parameters
    signautre: signature bytes object
  """
  if sig_type is None: sig_type = voc.scd.RSA_SIGNATURE_2018
  b64signature = base64.b64encode(signature_bytes)
  return {
    "@type": sig_type,
    voc.sec.CREATOR: creator,
    voc.sec.CREATED: created,
    voc.sec.SIGNATURE_VALUE: b64signature.decode('utf-8')
  }


def signature_bytes_from_ld_signature(ld_signature):
  """
  Parameters:
    ld_signatue: LinkedDataSignatures object containing a signatureValue
                 key representing a base64 encoded signature of the
                 document
  """
  b64signature = ld_signature[voc.sec.SIGNATURE_VALUE].encode('utf-8')
  return base64.b64decode(b64signature)
