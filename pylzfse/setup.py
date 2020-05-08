# this file is part of pylzfse.
#
# Copyright (c) 2016, 2017 Dima Krasner
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import os
from distutils.core import setup, Extension

lzfse_dir = os.path.join('lzfse', 'src')
lzfse_srcs = [os.path.join(lzfse_dir, x) for x in os.listdir(lzfse_dir) if x.endswith('.c') and x != 'lzfse_main.c']

lzfse = Extension('lzfse',
                   sources=lzfse_srcs + ['pylzfse.c'],
                   extra_compile_args=['-std=c99'],
                   include_dirs=[lzfse_dir],
                   language='c')

setup(name='pylzfse',
      version='0.2',
      license='MIT',
      author='Dima Krasner',
      author_email='dima@dimakrasner.com',
      description='Python bindings for the LZFSE reference implementation',
      ext_modules=[lzfse])
