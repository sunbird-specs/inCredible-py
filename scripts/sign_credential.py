import argparse
import copy
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization as s11n
from escs import credential as cred
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


def load_key_pair(private_key_filename, public_key_filename=None, password=None, backend_factory=default_backend):
  """Given a private key file and a public key file reads from file and returns
  the pair.

  Parameters:
    private_key_filename: the filename containing the private key
    public_key_filename: the filename containing the public key, if None, will
        default to the private_key_filename with the added extension '.pub'
    password: the password to the private key, None if there is no password.
    backend_factory: function which returns a backend
  """
  if not private_key_filename: raise ValueError('private_key_filename cannot be empty.')
  if public_key_filename is None:
    public_key_filename = private_key_filename + '.pub'

  with open(private_key_filename, 'rb') as privfile:
    pemlines = privfile.read()
  private_key = s11n.load_pem_private_key(pemlines, password, default_backend())

  with open(public_key_filename, 'rb') as pubfile:
    pemlines = pubfile.read()
  public_key = s11n.load_ssh_public_key(pemlines, default_backend())

  return private_key, public_key


def normalize_RsaSignature2018(credential):
  """The normalisation operation will produce a canonical
  representation of the credential according to the URDNA2015
  canonicalisation method.

  Returns:
    string containing the N-Quad representation of the normalised
    credential"""
  return jsonld.normalize(credential, options={
        'algorithm': 'URDNA2015',
        'format': 'application/n-quads'
  })


def create_RsaSignature2018(credential, private_key):
  """Given a JSON-LD credential and a RSAPrivateKey, will
  return the signature of the credential according to the
  RsaSignature2018 signature suite specification

  Parameters:
    credential: JSON-LD document in compact representation
    private_key: rsa.PrivateKey object

  Returns:
    bytes containing the signature
  """
  normalized = normalize_RsaSignature2018(credential)
  return private_key.sign(data=normalized.encode('utf-8'),
                          padding=padding.PKCS1v15(),
                          algorithm=hashes.SHA256())


def verify_RsaSignature2018(credential, public_key, signature):
  """Given a JSON-LD credential and a RSAPublicKey, will
  verify the signature of the credential according to the
  RsaSignature2018 signature suite specification

  Parameters:
    credential: JSON-LD document in compact representation
    public_key: rsa.PublicKey object
    signature: bytes of the signature
  """
  normalized = normalize_RsaSignature2018(credential)
  try:
    public_key.verify(signature, data=normalized.encode('utf-8'),
                      padding=padding.PKCS1v15(),
                      algorithm=hashes.SHA256())
    return True
  except InvalidSignature as e:
    return False


def sign_credential_in_file(filename, private_key, public_key, public_key_url):
  credential = cred.create_credential(filename)
  cred.set_issuer_public_key(credential, issuer_public_key=public_key,
                             issuer_public_key_url=public_key_url)

  signature = create_RsaSignature2018(credential, private_key)
  verified = verify_RsaSignature2018(credential, public_key, signature)
  assert verified == True
  print('Signature verified directly from signature bytes', file=sys.stderr)

  signed_credential = copy.deepcopy(credential)
  ld_signature = cred.create_ld_signature(signature, public_key_url)
  signed_credential['ocd:signature'] = ld_signature
  print(json.dumps(signed_credential, indent=2))

def verify_credential_in_file(filename):
  with open(filename, 'r') as f:
    signed_credential = json.load(f)

  # Removing the signature element from the credential for comparison
  unsigned_credential = copy.deepcopy(signed_credential)
  ld_signature = unsigned_credential.pop('ocd:signature')

  signature_bytes = cred.signature_bytes_from_ld_signature(ld_signature)
  public_key_from_doc = cred.rsa_public_key_from_issuer(cred.issuer_from_credential(unsigned_credential))
  verified_from_doc = verify_RsaSignature2018(unsigned_credential, public_key_from_doc, signature_bytes)
  assert verified_from_doc == True
  print('Signature verified after reading from credential', file=sys.stderr)


if __name__ == '__main__':
  parser = argparse.ArgumentParser()
  parser.add_argument('file', help='File to either sign or verify')
  parser.add_argument('-s', '--sign', action='store_true', dest='sign',
                      help='Toggle switch to enable signing. Requires --key option')
  parser.add_argument('-k', '--key', action='store', dest='keyfile', default=None,
                      help='Filepath to the private key to sign document with. '
                      'Required with --sign option')
  parser.add_argument('-v', '--verify', action='store_false', dest='sign',
                      help='Toggle switch to enable verification')

  args = parser.parse_args()

  if args.sign:
    private_key, public_key = load_key_pair(args.keyfile)
    public_key_url = 'https://example.com/keys/exampleKey'
    sign_credential_in_file(args.file, private_key, public_key, public_key_url)
  else:
    verify_credential_in_file(args.file)
