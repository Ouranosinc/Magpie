Contributing
============

Contributions are welcome, and they are greatly appreciated! Every
little bit helps, and credit will always be given.

You can contribute in many ways:

Types of Contributions
----------------------


Report Bugs
~~~~~~~~~~~

Report bugs at francois-xavier.derue@crim.ca.

If you are reporting a bug, please include:

* Your operating system name and version.
* Any details about your local setup that might be helpful in troubleshooting.
* Detailed steps to reproduce the bug.


Write Documentation
~~~~~~~~~~~~~~~~~~~

Magpie could always use more documentation, whether as part of the
official Magpie docs, in docstrings, or even on the web in blog posts,
articles, and such.

Submit Feedback
~~~~~~~~~~~~~~~

The best way to send feedback is to file an issue at francois-xavier.derue@crim.ca.

If you are proposing a feature:

* Explain in detail how it would work.
* Keep the scope as narrow as possible, to make it easier to implement.
* Remember that this is a volunteer-driven project, and that contributions
  are welcome :)


Get Started!
------------

Ready to contribute? Here's how to set up `magpie` for local development.

1. Clone the `keyword_worker_refcom` repo from the Mercurial repository.

    hg clone <repo_location>

2. Install your local copy and use a virtualenv. Assuming you have
   virtualenv installed, this is how you set up your fork for local
   development::
    
    $ cd magpie/
    $ virtualenv -p python 3.5 env
    $ source env/bin/activate.csh
    $ python setup.py develop

   Now you can make your changes locally.

3. When you're done making changes, check that your changes pass flake8 and the
   tests, including testing other Python versions with tox::

    $ flake8 magpie tests
    $ python setup.py test
    $ tox

   To get flake8 and tox, just pip install them into your virtualenv.

4. Commit your changes and push your branch to GitHub::

    $ hg commit -m "Your detailed description of your changes."

5. Submit a pull request to the author.


Pull Request Guidelines
-----------------------

Before you submit a pull request, check that it meets these guidelines:

1. The pull request should include tests.
2. If the pull request adds functionality, the docs should be updated. Put
   your new functionality into a function with a docstring, and add the
   feature to the list in README.rst.
3. The tests should work for the specifid version of Python for this project.


Tips
----

To run a subset of tests::

    $ python -m unittest tests.test_magpie
