"""
vocabs.py

credential vocabularies
"""


class sec:
  """Class representing the security vocabulry."""
  PREFIX = 'sec'
  IRI = 'https://w3id.org/security/v1#'
  # Properties
  CREATED = PREFIX+':created'
  CREATOR = PREFIX+':creator'
  OWNER = PREFIX+':owner'
  PUBLIC_KEY = PREFIX+':publicKey'
  PUBLIC_KEY_PEM = PREFIX+':publicKeyPem'
  SIGNATURE = PREFIX +':signature'
  SIGNATURE_VALUE = PREFIX +':signatureValue'
  # Types
  KEY = PREFIX+':Key'


class ob:
  """Class representing the openbadges vocabulary."""
  PREFIX = 'ob'
  IRI = 'https://w3id.org/openbadges/v2#'
  # Properties
  BADGE = PREFIX+':badge'
  ISSUER = PREFIX+':issuer'
  # Types
  CRYPROGRAPHIC_KEY = PREFIX+':CryptographicKey'


class scd:
  """Class representing the skill credentials vocabulary."""
  PREFIX = 'scd'
  IRI = 'https://skillcredentialspec.org/v1#'
  # Properties
  # Types
  RSA_SIGNATURE_2018 = PREFIX+':RsaSignature2018'


class schema:
  """Class representing the schema.org vocabulary."""
  PREFIX = 'schema'
  IRI = 'http://schema.org/'
  # Properties
  # Types
