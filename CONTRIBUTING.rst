Contributing
============

Contributions are welcome, and they are greatly appreciated! Every
little bit helps, and credit will always be given.

You can contribute in many ways:

Types of Contributions
----------------------


Report Bugs
~~~~~~~~~~~

Report bugs at francis.charette-migneault@crim.ca.

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

The best way to send feedback is to file an issue on https://github.com/Ouranosinc/Magpie.

If you are proposing a feature:

* Explain in detail how it would work.
* Keep the scope as narrow as possible, to make it easier to implement.
* Remember that this is a volunteer-driven project, and that contributions
  are welcome :)


Get Started!
------------

Ready to contribute? Here's how to set up `magpie` for local development.

1. Clone the repository from https://github.com/Ouranosinc/Magpie ::

    git clone https://github.com/Ouranosinc/Magpie


2. Install your local copy (see :doc:`installation`)

3. When you're done making changes, check that your changes pass code formatting and tests::

    make lint
    make test


4. Commit your changes and push your branch to GitHub.
5. Submit a pull request to the author (tests will run to evaluate that everything still works).


Pull Request Guidelines
-----------------------

Before you submit a pull request, check that it meets these guidelines:

1. The pull request should include tests.
2. If the pull request adds functionality, the docs should be updated. Put
   your new functionality into a function with a docstring, and add the
   feature to the list in :doc:`history` (under relevant category of section `Unreleased`).
3. The tests should work for the specified version of Python for this project.


Tips
----

To run a subset of tests::

    python -m unittest tests.test_magpie

