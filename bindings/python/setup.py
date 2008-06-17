from distutils.core import setup, Extension

auparse = Extension('auparse',
                    sources = ['auparse_python.c'],
                    include_dirs = ['../../auparse'],
                    libraries = ['auparse', 'audit'],
                    library_dirs= ['../../auparse/.libs', '../../lib/.libs'])

setup(name = 'auparse',
      version = '1.0',
      description = 'python binding for audit parsing (auparse)',
      ext_modules = [auparse])

