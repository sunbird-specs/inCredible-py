import argparse
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization as s11n
from skillcreds import credential as cred
from skillcreds import signatures
from skillcreds import suites
import json
import sys


def load_key_pair(private_key_filename, public_key_filename=None, password=None,
                  backend_factory=default_backend):
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
  """Saves an RSA private key and its public key component to a file
  optionally encrypting the private key with a password.

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


def sign_credential_in_file(filename, key_file, key_id):
  credential = cred.load_credential(filename)
  private_key, public_key = load_key_pair(key_file)
  cred.set_issuer_public_key(credential,
                             issuer_public_key=public_key,
                             issuer_key_id=key_id)

  signature = signatures.LinkedDataSignature(suites.RsaSignature2018())
  signed_credential = signature.sign(credential, private_key, key_id)
  print(json.dumps(signed_credential, indent=2))
  print('Credential created', file=sys.stderr)


def verify_credential_in_file(filename, trace=False):
  signed_credential = cred.load_credential(filename)
  signature = signatures.LinkedDataSignature(suites.RsaSignature2018(), trace)
  verified = signature.verify(signed_credential)
  assert verified == True

  sec_key, _ = cred.public_key_from_issuer(cred.issuer_from_credential(signed_credential))
  print('Credential signature in %(filename)r verified using public key: %(key_id)s' %
        {
          'filename': filename,
          'key_id': sec_key['@id']
        })


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
  parser.add_argument('-t', '--trace', action='store_true', dest='trace',
                      default=False, help='Turn on tracing mode')
  args = parser.parse_args()

  if args.sign:
    if not args.keyfile:
      parser.error('Signing mode requires keyfile(s) containing private key')
    sign_credential_in_file(args.file, args.keyfile, args.keyid)
  elif args.verify:
    verify_credential_in_file(args.file, args.trace)
  else:
    parser.error('Must choose one of sign (--sign) or verify (--verify) modes')
