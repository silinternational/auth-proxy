# Contributing to Auth Proxy

#### Table of Contents

[IDE configuration](#ide-configuration)

[Coding Style](#coding-style)


## IDE configuration

### Editorconfig

This project includes an .editorconfig file to enforce consistent formatting. See the [Editorconfig](https://editorconfig.org/) page for details. Enable this feature in your IDE to activate the configuration.

### Go formatting

Because Go has one code formatting standard, this project uses that
standard. To stay consistent, enable `goimports` in your editor or IDE to
format your code before it's committed. For example, in Goland, go to Settings -
Tools - File Watchers, add and enable `goimports`. Recommended, but not necessary: run [gofumpt](https://github.com/mvdan/gofumpt) as a file watcher to further format code in a consistent pattern.

## Coding Style

### Writing Tests
We try to write automated tests for everything possible. When deciding whether to test a particular situation in a
model or action, we typically test everything specific to the model in the model, and then test other behaviours
through the action. For example test model validation, data formatting, etc. at a model level, and then at an action
level test authentication, authorization, handling of error conditions, trying to access other user's resources, etc.
