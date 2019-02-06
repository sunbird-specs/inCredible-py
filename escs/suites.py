"""
suites.py

module implementing the rsa_signature_2018 signature suite and others
"""
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from pyld import jsonld

class SignatureSuite(object):
  def normalize(self, document):
    raise NotImplementedError()

  def hash(self, document):
    raise NotImplementedError()

  def sign(self, document):
    raise NotImplementedError()


class RsaSignature2018(SignatureSuite):
  def normalize(self, document):
    """The normalisation operation will produce a canonical
    representation of the document according to the URDNA2015
    canonicalisation method.

    Returns:
      string containing the N-Quad representation of the normalised
      document"""
    return jsonld.normalize(document, options={
        'algorithm': 'URDNA2015',
        'format': 'application/n-quads'
    })

  def hash(self, message):
    """The hashing operation will produce a message digest using the
    SHA256 digest algorithm."""
    hasher = hashes.Hash(hashes.SHA256(), backend=default_backend())
    hasher.update(message)
    return hasher.finalize()

  def sign(self, tbs, private_key):
    """The signing operation will produce signature bytes using the
    RS256 JSON Web Signature Algorithm."""
    return private_key.sign(data=tbs,
                            padding=padding.PKCS1v15(),
                            algorithm=hashes.SHA256())

  def verify(self, signature_value, tbv, public_key):
    """The verification operation will verify signature bytes using the
    RS256 JSON Web Signature Algorithm."""
    public_key.verify(signature_value, data=tbv,
                      padding=padding.PKCS1v15(),
                      algorithm=hashes.SHA256())
