SecondGuard
===========

Getting Started
---------------

This library makes rate-limited encryption really simple!

Ask SecondGuard for a key to encrypt the secret locally, and then encrypt the secret for storage in the database of your choice:

.. code-block:: python

    >>> from secondguard import sg_encrypt_secret
    >>>
    >>> to_save_in_db = sg_encrypt_secret('Attack at dawn!', 'YOUR_SEED_PUB_HASH', 'YOUR API_TOKEN')
    >>> print(to_save_in_db)
    SG-AESCFB-v1$bytes$e6febe465a7e957ec221ef959cf167bb1a99f8fa7b826eefe689897ce4c6bc5f$5d99ef93c817caad405d5ae3ff076c863c33bae49d39a45fd3f2b9c1d77f5a45$Ma5T5YUKVxLHj8PLm9a0sg==$y5hrM5c4faEHlzUCRQmU


When you want to decrypt that data in the future, you'll ask SecondGuard for the original key to decrypt:

.. code-block:: python

    >>> from secondguard import sg_decrypt_secret
    >>>
    >>> sg_decrypt_secret(to_save_in_db, 'YOUR_API_TOKEN')
    'Attack at dawn!'

You can also decrypt locally using your private seed. To verify this is working as designed, turn off your internet connection(or audit the code path) and then run:

.. code-block:: python

    >>> from secondguard import sg_decrypt_from_priv_seed
    >>>
    >>> sg_decrypt_from_priv_seed(to_save_in_db, 'YOUR_PRIVATE_SEED')
    'Attack at dawn!'

See ``test_secondguard.py`` for examples for all methods.


Installation
------------

To get started:

.. code-block:: bash

    $ pip install secondgaurd

If you don't have `pip` pre-installed on your machine you can `install pip here <http://pip.readthedocs.org/en/stable/installing/>`_. If for some reason `pip` doesn't work you can use `easy_install`, but `you really shouldn't do that <http://stackoverflow.com/questions/3220404/why-use-pip-over-easy-install>`_.

Note that if you use an outdated version of pip you may get a scary ``InsecurePlatformWarning`` warning installing any package (including ``secondguard``). As always, you should upgrade your pip to the latest version before installing any new software:

.. code-block:: bash

    $ pip install --upgrade pip

Advanced users can download the source code and build from source:

.. code-block:: bash

    $ python setup.py build
    $ python setup.py install

You can also use ``python3`` (replace ``pip3`` with ``pip``).
