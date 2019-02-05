from distutils.core import setup

setup(name='escs',
      version='0.0',
      description='Electronic Skills Credential Specification Utilities',
      url='https://bharatskills.gov.in/skills-credentials',
      packages=['escs'],
      requires=[
        "cryptography (>=2.5, <2.6)",
        "PyLD (>=1.0.4, <1.1)",
        "requests (>=2.21.0, <2.22)",
      ],
      scripts=['scripts/sign_credential.py'])
