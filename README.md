# Electronic Skill Credential Specification
Sample Python3 code to create and verify a digitally signed skill credential.

## Using the sample scripts
These instructions assume that you have cloned the respository locally, and are in the root of the repo

1. Create a new python3 [virtualenv](https://virtualenv.pypa.io/en/latest/)
2. Once the virtualenv is setup and activated, install the dependencies for the scripts

```shell
$ pip3 install cryptography pyld
```

3. Run the script

```shell
$ python3 scripts/sign_credential.py > cred.json
```

This should run the script and output a signed credential to a file called `cred.json` in the present directory.
