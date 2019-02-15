import argparse
from pyld import jsonld
from skillcreds import credential as cred
import sys


def normalize_credential_in_file(filename, algorithm, trace=False):
  credential = cred.load_credential(filename)
  normalized = jsonld.normalize(credential, options={
                  'algorithm': algorithm,
                  'format': 'application/n-quads'
                })
  print(normalized)
  print('Credential normalized using '+algorithm, file=sys.stderr)


if __name__ == '__main__':
  parser = argparse.ArgumentParser(description="Normalize JSON-LD documents")
  parser.add_argument('file', help='File containing JSON-LD to normalize')
  alg = parser.add_mutually_exclusive_group()
  alg.add_argument('--urdna2015', '--d15', action='store_true', default=True,
                   help='Use the URDNA2105 algorithm to normalize the document')
  alg.add_argument('--urgna2012', '--g12', action='store_true',
                   help='Use the URGNA2012 algorithm to normalize the document')
  parser.add_argument('-t', '--trace', action='store_true', dest='trace',
                      default=False, help='Turn on tracing mode')
  args = parser.parse_args()

  if args.urgna2012:
    alg = 'URGNA2012'
  elif args.urdna2015:
    alg = 'URDNA2015'

  normalize_credential_in_file(args.file, alg, args.trace)
