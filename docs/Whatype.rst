=======
Whatype
=======

Whatype is an independent file type identification python library.
File Type Identification provides “magic”-like analysis of a file’s content to determine its true payload.

After spending some time trying to find a file identification library that suits CapTipper's needs (cross-platform, cross-environment, accepts file stream, and does not require too much dependencies), I came up short and decided to write one myself.
Whatype was originally developed for `CapTipper <https://github.com/omriher/CapTipper>`__ but is also an independent library and can be found on `GitHub`__.


The magic bytes signatures are stored in ``magics.csv``, with the format of:

.. code:: python

    File Description, Magic bytes (Offset 0), Extenstion, Obligatory strings

My initial goal was only to use it as part of CapTipper, so currently it supports ~50 of the most common and relevant file formats:
Executables, PDF, JAVA, SWF, Silverlight, HTML, ZIP, and more…

Installation
-------------
.. code:: python

    setup.py install

Usage
-----
Load Whatype library

.. code:: python

    from whatype import Whatype
    WTlib = Whatype() # Uses default magics.csv shipped with the library

Identify file from FileSystem

.. code:: python

    print WTlib.identify_file("file.ext")

Identify file from Buffer

.. code:: python

    with open("file.ext",'rb') as f:
      data = f.read()
    print WTlib.identify_buffer(data)

Results returns in the form of a tuple:

.. code:: python

    (File Description, File Extenstion)

**Example**

.. code:: python

    >>> from whatype import Whatype
    >>> WTlib = Whatype()
    >>> WTlib.identify_file("C:\\BinaryFile.exe")
    ('Windows executable file', 'EXE')

    >>> with open(r"C:\\java-archive.jar",'rb') as f:
    ...     cont = f.read()
    ...
    >>> WTlib.identify_buffer(cont)
    ('Java archive', 'JAR')


I would like to invite the open-source community to contribute to the Whatype project (currently in beta release phase) and help create a broader and more accurate signature base, improve the identification performance and hopefully help serve other developers that encounter the same problem.

.. _Whatype: https://github.com/omriher/Whatype
__ Whatype_