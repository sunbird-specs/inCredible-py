"""
signatures.py

module implementing the rsa_signature_2018 signature suite and others
"""
import binascii
import copy
from cryptography.exceptions import InvalidSignature
from escs import credential as cred
import datetime
import sys


class SignatureProtocol(object):
  def create_verify_hash(self, document):
    raise NotImplementedError()

  def sign(self, document):
    raise NotImplementedError()

  def verify(self, document):
    raise NotImplementedError()


class LinkedDataSignature(SignatureProtocol):

  def __init__(self, suite):
    self.suite = suite

  def create_verify_hash(self, canonical, creator, created=None, nonce=None, domain=None):
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

    suite = self.suite
    # Step 4.1 Canonicalise the options
    canonicalized_options = suite.normalize(options)
    # Step 4.2 compute the hash of the options
    output = suite.hash(canonicalized_options.encode('utf-8'))
    # Step 4.3 compute the hash of the document and append
    output += suite.hash(canonical.encode('utf-8'))
    return output

  def sign(self, credential, private_key, key_id):
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
    suite = self.suite
    # Following the algorithm at:
    # https://w3c-dvcg.github.io/ld-signatures/#signature-algorithm
    # 1 Feb 2019
    # Step 1: copy the credential
    output = copy.deepcopy(credential)
    # Step 2: canonicalise
    canonicalised = suite.normalize(credential)
    # Step 3: create verify hash, setting the creator and created options
    created = datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%S%Z')
    tbs = self.create_verify_hash(canonicalised, creator=key_id, created=created)
    # Step 4: sign tbs using private key and signature algorithm
    signature_value = suite.sign(tbs, private_key)
    # Step 5: add a signature node to output
    output['ocd:signature'] = cred.create_ld_signature(signature_value,
                                                       creator=key_id,
                                                       created=created)
    return output

  def verify(self, signed_credential):
    """Given a signed JSON-LD credential, will verify the signature
    according to the LinkedDataSignature 1.0 specification.
    This implementation using the RsaSignature2018
    signature suite.

    Parameters:
      signed_credential: signed JSON-LD document in compact representation

    Returns:
      True if the signature is valid, False otherwise
    """
    suite = self.suite
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
    tbv = self.create_verify_hash(canonicalised,
                                  creator=signature.get('sec:creator', ''),
                                  created=signature.get('sec:created', ''))
    # Step 6: verify tbv using the public key
    try:
      signature_value = cred.signature_bytes_from_ld_signature(signature)
      suite.verify(signature_value, tbv, rsa_public_key)
      return True
    except InvalidSignature as e:
      print(e.msg, file=sys.stderr)
      return False
    except binascii.Error as e:
      print("ERROR: Signature invalid: "+str(e), file=sys.stderr)
      return False
