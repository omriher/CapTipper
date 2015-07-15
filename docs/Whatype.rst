=======
Whatype
=======

Whatype is an independent file type identification python library.
Whatype was originally developed for `CapTipper <https://github.com/omriher/CapTipper>`__ but is also an independent library and can be found on `GitHub`__.


The magic bytes signatures are stored in ``magics.csv``, with the format of:

.. code:: python

    File Description, Magic bytes (Offset 0), Extenstion, Obligatory strings

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




.. _Whatype: https://github.com/omriher/Whatype
__ Whatype_