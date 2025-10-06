# Contributing to SD-JWT

We love your input! We want to make contributing to this project as easy and transparent as possible, whether it's:

- Reporting a bug
- Discussing the current state of the code
- Submitting a fix
- Proposing new features
- Becoming a maintainer

## We Develop with Github

We use github to host code, to track issues and feature requests, as well as accept pull requests.

## We Use [Github Flow](https://guides.github.com/introduction/flow/index.html), So All Code Changes Happen Through Pull Requests

Pull requests are the best way to propose changes to the codebase (we use [Github Flow](https://guides.github.com/introduction/flow/index.html)). We actively welcome your pull requests:

1. Fork the repo and create your branch from `main`.
2. If you've added code that should be tested, add tests.
3. If you've changed APIs, update the documentation.
4. Ensure the test suite passes.
5. Make sure your code lints.
6. Issue that pull request!

## Any contributions you make will be under the Apache 2.0 Software License

In short, when you submit code changes, your submissions are understood to be under the same [Apache 2.0 License](http://www.apache.org/licenses/) that covers the project. Feel free to contact the maintainers if that's a concern.

## Report bugs using Github's [issues](https://github.com/openwallet-foundation/sd-jwt-js/issues)

We use GitHub issues to track public bugs. Report a bug by opening a new issue it's that easy!

## Write bug reports with detail, background, and sample code

**Great Bug Reports** tend to have:

- A quick summary and/or background
- Steps to reproduce
  - Be specific!
  - Give sample code if you can.
- What you expected would happen
- What actually happens
- Notes (possibly including why you think this might be happening, or stuff you tried that didn't work)

## Release procedure

Each PR to the `main` branch has to pass the `build`, `test`, `lint` and `code coverage` steps from the CI. The PR also needs a review from one authorized person.
All commits needs to be signed to pass the DCO check.

After the PR is merged, a new `next` version is build and deployed to `npmjs` for all packages with the `next` tag.

The release of a new version is done by running the `release` workflow manually. This workflow can only be triggered successfully by an authorized person that is listed inside the `CODEOWNERS` file. The test and coverage steps are executed again and the new version is published to `npmjs` for all packages with the `latest` tag. The version number is calculated based on the commits since the last release and the `semver` rules.