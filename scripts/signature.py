import argparse
import copy
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization as s11n
from escs import credential as cred
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


def save_key_pair(private_key, private_key_filename, password=None, public_key_filename=None):
  """
  Saves an RSA private key and its public key component to a file optionally
  encrypting the private key with a password.

  Parameters:
    private_key: an RSA private key
    private_key_filename: the file where the private key will be output
    password: the bytes for the password, None if not encypted
    public_key_filename: alternate filename for the public key. If omitted
        will use the private_key_filename with '.pub' as the extension
  """
  if not private_key_filename: raise ValueError('private_key_filename cannot be empty.')
  if public_key_filename is None:
    public_key_filename = private_key_filename + '.pub'
  public_key = private_key.public_key()

  with open(private_key_filename, 'wb') as privfile:
    alg = s11n.NoEncryption() if password is None else s11n.BestAvailableEncryption(password)
    private_bytes = private_key.private_bytes(encoding=s11n.Encoding.PEM,
                                             format=s11n.PrivateFormat.PKCS8,
                                             encryption_algorithm=alg)
    privfile.write(private_bytes)

  with open(public_key_filename, 'wb') as pubfile:
    public_bytes = public_key.public_bytes(encoding=s11n.Encoding.OpenSSH,
                                           format=s11n.PrivateFormat.OpenSSH)
    pubfile.write(public_bytes)


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


def sign_credential_in_file(filename, keyfile, public_key_url):
  credential = cred.create_credential(filename)
  private_key, public_key = load_key_pair(keyfile)
  cred.set_issuer_public_key(credential, issuer_public_key=public_key,
                             issuer_public_key_url=public_key_url)

  signature = create_RsaSignature2018(credential, private_key)
  verified = verify_RsaSignature2018(credential, public_key, signature)
  assert verified == True
  print('Credential signature bytes verified using public key in %s.pub' % (keyfile,),
        file=sys.stderr)

  signed_credential = copy.deepcopy(credential)
  ld_signature = cred.create_ld_signature(signature, public_key_url)
  signed_credential['ocd:signature'] = ld_signature
  print(json.dumps(signed_credential, indent=2))
  print('Credential created', file=sys.stderr)


def verify_credential_in_file(filename):
  with open(filename, 'r') as f:
    signed_credential = json.load(f)


  unsigned_credential = copy.deepcopy(signed_credential)
  # Removing the signature element from the credential for comparison
  ld_signature = unsigned_credential.pop('ocd:signature')

  signature_bytes = cred.signature_bytes_from_ld_signature(ld_signature)
  sec_key, rsa_public_key = cred.public_key_from_issuer(cred.issuer_from_credential(unsigned_credential))
  verified_from_doc = verify_RsaSignature2018(unsigned_credential, rsa_public_key, signature_bytes)
  assert verified_from_doc == True

  print('Credential signature in %(filename)r verified using public key: %(key_id)s' %
        {
          'filename': filename,
          'key_id': sec_key['@id']
        }, file=sys.stderr)


if __name__ == '__main__':
  parser = argparse.ArgumentParser(description="Manipulate JSON-LD signatures -- sign or verify")
  parser.add_argument('file', help='File to either sign or verify')
  mode = parser.add_mutually_exclusive_group()
  mode.add_argument('-s', '--sign', action='store_true',
                      help='Run in signing mode. Requires --key option')
  mode.add_argument('-v', '--verify', action='store_true',
                      help='Run in verification mode')
  parser.add_argument('-k', '--key', action='store', dest='keyfile', default=None,
                      help='Filepath to the private key to sign document with. '
                      'Public key should found at <KEYFILE>.pub.'
                      'Required with --sign option')

  args = parser.parse_args()
  if args.sign:
    if not args.keyfile:
      parser.error('Signing mode requires keyfile(s) containing private key')

    public_key_url = 'https://example.com/keys/exampleKey'
    sign_credential_in_file(args.file, args.keyfile, public_key_url)
  elif args.verify:
    verify_credential_in_file(args.file)
  else:
    parser.error('Must choose one of sign (--sign) or verify (--verify) modes')
