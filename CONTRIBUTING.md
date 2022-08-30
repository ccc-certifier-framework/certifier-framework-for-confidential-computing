# Contributing to certifier-framework-for-confidential-computing

The certifier-framework-for-confidential-computing project team welcomes
contributions from the community. Before you start working with this project
please read and sign our Contributor License Agreement
(https://cla.vmware.com/cla/1/preview). If you wish to contribute code and
you have not signed our Contributor Licence Agreement (CLA), our bot will
prompt you to do so when you open a Pull Request. For any questions about
the CLA process, please refer to our [FAQ](https://cla.vmware.com/faq).
All contributions to this repository must be signed as described
on that page. Your signature certifies that you wrote the patch
or have the right to pass it on as an open-source patch.

## Contribution Flow

This is a rough outline of what a contributor's workflow looks like:

- Create a topic branch from where you want to base your work
- Make commits of logical units
- Make sure your commit messages are in the proper format (see below)
- Push your changes to a topic branch in your fork of the repository
- Submit a pull request

Example:

``` shell
git remote add upstream https://github.com/vmware-research/certifier-framework-for-confidential-computing.git
git checkout -b my-new-feature main
git commit -a
git push origin my-new-feature
```

### Staying In Sync With Upstream

When your branch gets out of sync with the vmware-research/main branch, use the following to update:

``` shell
git checkout my-new-feature
git fetch -a
git pull --rebase upstream main
git push --force-with-lease origin my-new-feature
```

### Updating pull requests

If your PR fails to pass CI or needs changes based on code review, you'll
most likely want to squash these changes into existing commits.

If your pull request contains a single commit or your changes are related
to the most recent commit, you can simply amend the commit.

``` shell
git add .
git commit --amend
git push --force-with-lease origin my-new-feature
```

If you need to squash changes into an earlier commit, you can use:

``` shell
git add .
git commit --fixup <commit>
git rebase -i --autosquash main
git push --force-with-lease origin my-new-feature
```

Be sure to add a comment to the PR indicating your new changes are ready to
review, as GitHub does not generate a notification when you git push.

### Coding Style

We use Google's code style for C++ and Go and the Linux code style for
C.  Before you check in new features, you should have tests and you
should run all the tests.  When possible, we use Google's test
framework (gtest), although some tests are stand-alone.  Even if
functionality does not change, we welcome additional tests.  The
Test goal is: "If the tests pass, changes are compatible."

Before a check-in you should make sure certifier_tests pass with
SEV defined along with test_channel.exe,
sample_app/simple_app/example_app.exe,
application_service/app_service.exe and
simple_app_under_app_service/service_example_app.exe.


### Formatting Commit Messages

We follow the conventions on [How to Write a Git Commit Message]
(http://chris.beams.io/posts/git-commit/).

Be sure to include any related GitHub issue references in the
commit message.  See [GFM syntax]
(https://guides.github.com/features/mastering-markdown/#GitHub-flavored-markdown)
for referencing issues and commits.

## Reporting Bugs and Creating Issues

When opening a new issue, try to roughly follow the commit message
format conventions above.
