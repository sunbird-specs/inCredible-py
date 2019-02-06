import argparse
import copy
from escs import credential as cred
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization as s11n
import datetime
import json
from pyld import jsonld
from escs import suites
import sys


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


def create_verify_hash(suite, canonical, creator, created=None, nonce=None, domain=None):
  """Given a canonicalised JSON-LD document, returns the verification
  hash of the document and the options passed in accoding to the
  LinkedDataSignatures specification.

  Returns:
    bytes containing the hash of the document and the options
  """
  # Following the algorithm at
  # https://w3c-dvcg.github.io/ld-signatures/#create-verify-hash-algorithm
  # 1 Feb 2019
  # Add a datetime if one is not provided
  if created is None: created = datetime.datetime.utcnow()
  # Creating a copy of input options
  options = {
    'sec:creator': creator,
    'sec:created': created
  }
  if nonce is not None: options['sec:nonce'] = nonce
  if domain is not None: options['sec:domain']: domain

  # Step 4.1 Canonicalise the options
  canonicalized_options = suite.normalize(options)
  # Step 4.2 compute the hash of the options
  output = suite.hash(canonicalized_options.encode('utf-8'))
  # Step 4.3 compute the hash of the document and append
  output += suite.hash(canonical.encode('utf-8'))
  return output


def sign_with_LinkedDataSignature(credential, private_key, key_id, suite=None):
  """Given a JSON-LD credential and a RSAPrivateKey, will return the
  signed credential according to the LinkedDataSignature 1.0
  specification. This implementation using the RsaSignature2018
  signature suite.

  Parameters:
    credential: JSON-LD document in compact representation
    private_key: rsa.PrivateKey object
    key_id: The JSON-LD @id (identifier) of the private/public keypair
        used

  Returns:
    signed credential
  """
  if suite is None: suite = suites.RsaSignature2018()

  # Following the algorithm at:
  # https://w3c-dvcg.github.io/ld-signatures/#signature-algorithm
  # 1 Feb 2019
  # Step 1: copy the credential
  output = copy.deepcopy(credential)
  # Step 2: canonicalise
  canonicalised = suite.normalize(credential)
  # Step 3: create verify hash, setting the creator and created options
  created = datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%S%Z')
  tbs = create_verify_hash(suite, canonicalised, creator=key_id, created=created)
  # Step 4: sign tbs using private key and signature algorithm
  signature_value = suite.sign(tbs, private_key)
  # Step 5: add a signature node to output
  output['ocd:signature'] = cred.create_ld_signature(signature_value,
                                                     creator=key_id,
                                                     created=created)
  return output


def verify_LinkedDataSignature(signed_credential, suite=None):
   """Given a signed JSON-LD credential, will verify the signature
  according to the LinkedDataSignature 1.0 specification.
  This implementation using the RsaSignature2018
  signature suite.

  Parameters:
    signed_credential: signed JSON-LD document in compact representation

  Returns:
    True if the signature is valid, False otherwise
  """
  if suite is None: suite = suites.RsaSignature2018()

  # Following the algorithm at:
  # https://w3c-dvcg.github.io/ld-signatures/#signature-verification-algorithm
  # 1 Feb 2019
  # Step 1: Get the cryptographic key and rsa object
  # Step 1b: verifying owner from sec_key is left as an exercise
  sec_key, rsa_public_key = cred.public_key_from_issuer(cred.issuer_from_credential(signed_credential))
  # Step 2: copy signed document into document
  credential = copy.deepcopy(signed_credential)
  # Step 3: removing the signature node from the credential for comparison
  signature = credential.pop('ocd:signature')
  # Step 4: canonicalise
  canonicalised = suite.normalize(credential)
  # Step 5: create verify hash, setting the creator and created options
  tbv = create_verify_hash(suite, canonicalised,
                           creator=signature.get('sec:creator', ''),
                           created=signature.get('sec:created', ''))
  # Step 6: verify tbv using the public key
  try:
    signature_value = cred.signature_bytes_from_ld_signature(signature)
    suite.verify(signature_value, data=tbv, public_key)
    return True
  except InvalidSignature as e:
    return False


def sign_credential_in_file(filename, key_file, key_id):
  credential = cred.create_credential(filename)
  private_key, public_key = load_key_pair(key_file)
  cred.set_issuer_public_key(credential,
                             issuer_public_key=public_key,
                             issuer_key_id=key_id)

  signed_credential = sign_with_LinkedDataSignature(credential, private_key, key_id)
  print(json.dumps(signed_credential, indent=2))
  print('Credential created', file=sys.stderr)


def verify_credential_in_file(filename):
  with open(filename, 'r') as f:
    signed_credential = json.load(f)

  verified = verify_LinkedDataSignature(signed_credential)
  assert verified == True

  sec_key, _ = cred.public_key_from_issuer(cred.issuer_from_credential(signed_credential))
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
                      'Required in --sign mode ')
  parser.add_argument('--keyid', action='store', dest='keyid',
                      default='https://example.com/keys/exampleKey',
                      help='Identifier for the key which will be used as '
                      'issuer.publicKey.@id')
  args = parser.parse_args()

  if args.sign:
    if not args.keyfile:
      parser.error('Signing mode requires keyfile(s) containing private key')
    sign_credential_in_file(args.file, args.keyfile, args.keyid)
  elif args.verify:
    verify_credential_in_file(args.file)
  else:
    parser.error('Must choose one of sign (--sign) or verify (--verify) modes')
