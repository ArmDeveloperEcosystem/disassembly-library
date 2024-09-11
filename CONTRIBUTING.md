# Contributing

Arm Disassembly Library is licensed under the [Apache-2.0 License](LICENSE). By contributing to this project, you agree to the license and copyright terms.

All contributions will be released under these terms, as per the [Developer Certificate of Origin](DCO.md).

# Getting Started

* Make sure you have a [GitHub account](https://github.com/login).
* Clone the repo to your own machine.
* Create a local branch based on the [Arm Disassembly Library](https://github.com/ArmDeveloperEcosystem/disassembly-library) `main` branch.

# Making Changes

* Make commits of logical units. See these general [Git guidelines](http://git-scm.com/book/ch5-2.html) for contributing to a project.
* Follow the [style guidelines](#style-guidelines) section below.
* Keep commits focused on their main purpose. If you need to fix another bug or make another enhancement, please address it using a separate pull request.
* Avoid using a long series of commits. Consider whether some commits should be squashed together or addressed in a separate pull request.
* Make sure your commit messages are in the proper format.
* Where appropriate, please update the documentation.
* Ensure that each changed file has the correct copyright and license information:
 * Files that entirely consist of contributions to this project should have a copyright notice and Apache-2.0 SPDX license identifier.
 * Files that contain changes to imported Third Party IP files should retain their original copyright and license notices.
* For pull requests with multiple commits, it is recommended that you make all the documentation changes (and nothing else) in the last commit of the series.
* Please test your changes.

# Style Guidelines

The source code must use the UTF-8 encoding. Comments, documentation and strings may use non-ASCII characters when required.

## C/C++
* Follow the style in existing source files.

## Python
* For Python, follow the style in existing source files and the PEP8 specification.
* Code should be linted using `pylint` and the provided [.pylintrc file](python/.pylintrc).

# Submitting Changes

* Ensure that each commit in the series has at least one `Signed-off-by:` line, using your real name and email address. The names in the `Signed-off-by:` and `Author:` lines must match. If anyone else contributes to the commit, they must also add their own `Signed-off-by:` line. By adding this line the contributor certifies the contribution is made under the terms of the [Developer Certificate of Origin (DCO)](DCO.md).
* Push your local changes to a new branch (this may require [adding a new SSH key to your GitHub account](https://docs.github.com/en/authentication/connecting-to-github-with-ssh/adding-a-new-ssh-key-to-your-github-account).
* [Create a pull request](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/proposing-changes-to-your-work-with-pull-requests/creating-a-pull-request) from your branch to the [Arm Disassembly Library](https://github.com/ArmDeveloperEcosystem/disassembly-library) `main` branch.
* The changes will then undergo further review and testing by the maintainers. Any review comments will be made as comments on the PR. This may require you to make further changes.
* When the changes are accepted, the maintainers will integrate them.
* If the MR is not based on a recent commit, the maintainers may rebase it onto the `main` branch first, or ask you to do this.
* If the MR cannot be automatically merged, the maintainers will ask you to rebase it onto the `main` branch.
* If the maintainers find any issues after merging, they may remove the commits and ask you to create a new pull request to resolve the problem(s).

> [!TIP]
> Consider setting your user.name and user.email in your git config; then you can sign your commit automatically with git commit -s