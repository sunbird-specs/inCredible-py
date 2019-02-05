# Electronic Skill Credential Specification
Sample Python3 code to create and verify a digitally signed skill credential.

## Using the sample scripts
These instructions assume that you have cloned the respository locally, and are in the root of the repo

1. Create a new python3 [virtualenv](https://virtualenv.pypa.io/en/latest/)
2. Once the virtualenv is setup and activated, install the package and the scripts

```shell
$ pip3 install .
```

3. Run the script to sign a credential given a private key and public key. The public key should be in the same directory as the public key with the extension `.pub`

```shell
$ python3 scripts/signature.py --key <path_to_private_key> --sign <path_to_credential_file>
```

This will run the script and output a signed version of the credential in `credential_file`. This output can be re-directed to a file:

```shell
$ python3 scripts/signature.py --key <path_to_private_key> --sign <path_to_credential_file> > signed_credential.json
```

4. Verify the signed document using the public key contained in the credential

```shell
$ python3 scripts/signature.py --verify signed_credential.json
```
