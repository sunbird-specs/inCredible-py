from distutils.core import setup

setup(name='skillcreds',
      version='0.1',
      description='Electronic Skills Credential Specification Utilities',
      url='https://bharatskills.gov.in/skills-credentials',
      packages=['skillcreds'],
      requires=[
        "cryptography (>=2.5, <2.6)",
        "PyLD (>=1.0.4, <1.1)",
        "requests (>=2.21.0, <2.22)",
      ],
      scripts=['scripts/sign.py'])
