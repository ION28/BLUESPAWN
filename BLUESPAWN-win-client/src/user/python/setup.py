from distutils.core import setup, Extension

module = Extension('bluespawn',
                    sources = ['bs_shims.c'])

setup (name = 'bluespawn',
       version = '1.0',
       description = 'Python interface for BLUESPAWN',
       ext_modules = [module],
	   data_files=[
	       ('.', ['BLUESPAWN-client-lib.dll']),
	   ])