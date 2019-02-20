"""
signatures.py

module implementing the rsa_signature_2018 signature suite and others
"""
import binascii
import base64
import copy
from cryptography.exceptions import InvalidSignature
import datetime
from skillcreds import credential as cred
from skillcreds.vocabs import sec
import sys


class SignatureProtocol(object):
  def create_verify_hash(self, document, creator, created=None, nonce=None, domain=None):
    raise NotImplementedError()

  def sign(self, document, private_key, key_id):
    raise NotImplementedError()

  def verify(self, document):
    raise NotImplementedError()


class LinkedDataSignature(SignatureProtocol):

  def __init__(self, suite, trace=False):
    self.suite = suite
    self.trace = trace

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
    trace = self.trace
    if created is None: created = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S%Z')
    # Creating a copy of input options
    options = {
      sec.CREATOR: creator,
      sec.CREATED: created
    }
    if nonce is not None: options[sec.NONCE] = nonce
    if domain is not None: options[sec.DOMAIN]: domain

    suite = self.suite
    # Step 4.1 Canonicalise the options
    canonicalised_options = suite.normalize(options)
    if trace:
      print("Norm opts:\n"+canonicalised_options, file=sys.stderr)
    # Step 4.2 compute the hash of the options
    output = suite.hash(canonicalised_options.encode('utf-8'))
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
    trace = self.trace
    # Following the algorithm at:
    # https://w3c-dvcg.github.io/ld-signatures/#signature-algorithm
    # 1 Feb 2019
    # Step 1: copy the credential
    output = copy.deepcopy(credential)
    # Step 2: canonicalise
    canonicalised = suite.normalize(credential)
    if trace:
      print("Normalized:\n"+canonicalised, file=sys.stderr)
    # Step 3: create verify hash, setting the creator and created options
    created = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S%Z')
    tbs = self.create_verify_hash(canonicalised, creator=key_id, created=created)
    if trace:
      print("TBS:\n"+base64.b64encode(tbs).decode('utf-8'), file=sys.stderr)
    # Step 4: sign tbs using private key and signature algorithm
    signature_value = suite.sign(tbs, private_key)
    # Step 5: add a signature node to output
    output[sec.SIGNATURE] = cred.create_ld_signature(signature_value,
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
    trace = self.trace
    # Following the algorithm at:
    # https://w3c-dvcg.github.io/ld-signatures/#signature-verification-algorithm
    # 1 Feb 2019
    # Step 1: Get the cryptographic key and rsa object
    # Step 1b: verifying owner from sec_key is left as an exercise
    sec_key, rsa_public_key = cred.public_key_from_issuer(cred.issuer_from_credential(signed_credential))
    # Step 2: copy signed document into document
    credential = copy.deepcopy(signed_credential)
    # Step 3: removing the signature node from the credential for comparison
    signature = credential.pop(sec.SIGNATURE);
    if sec.CREATOR not in signature: raise ValueError('Signed credential signature is missing '+sec.CREATOR+' field')
    if sec.CREATED not in signature: raise ValueError('Signed credential signature is missing '+sec.CREATED+' field')
    # Step 4: canonicalise
    canonicalised = suite.normalize(credential)
    if trace:
      print("Normalized:\n"+canonicalised, file=sys.stderr)
    # Step 5: create verify hash, setting the creator and created options

    tbv = self.create_verify_hash(canonicalised,
                                  creator=signature[sec.CREATOR],
                                  created=signature[sec.CREATED])
    if trace:
      print("TBV:\n"+base64.b64encode(tbv).decode('utf-8'), file=sys.stderr)
    # Step 6: verify tbv using the public key
    try:
      signature_value = cred.signature_bytes_from_ld_signature(signature)
      suite.verify(signature_value, tbv, rsa_public_key)
      return True
    except InvalidSignature as e:
      print("ERROR: Signature invalid!", file=sys.stderr)
      return False
    except binascii.Error as e:
      print("ERROR: Signature invalid: "+str(e), file=sys.stderr)
      return False
