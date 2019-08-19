
# Introduction
This document explains how to use the erl-otp library.

# HOTP
**TODO**

# TOTP
The TOTP implementation is based on [RFC 6238](https://tools.ietf.org/html/rfc6238).

The `totp_validator` module is used to authenticate passwords. First use
`totp_validator:init/1` to create a new validator (or `totp_validator:init/2'
to provide custom settings), then call `totp_validator:authenticate/2` each
time a password has to be validated.

Example:

```erlang
Key = <<"Hello world">>,
Validator = totp_validator:init(Key, [{nb_digits, 6}]),
{Validator2, ValidationResult} = totp_validator:authenticate(Validator, 123456).
```

The validation result is either `valid` or `invalid`.

The following validator settings are supported:

| Setting        | Type      | Description                                         | Default value |
| -------        | ----      | -----------                                         | ------------- |
| `nb_digits`    | integer   | The number of digits in a password.                 | 6             |
| `initial_time` | timestamp | The initial timestamp used to compute time periods. | 0             |
| `time_step`    | integer   | The length of a time period in seconds.             | 30            |
| `look_behind`  | integer   | The number of past periods to check for validity.   | 1             |
| `look_ahead`   | integer   | The number of future periods to check for validity. | 1             |

## OTP URI
It is possible to generate OTPAUTH URI using the
`hotp_validator:otpauth_uri/3` and `totp_validator:otpauth_uri/3`
functions. The format of these URIs is defined in the [Google Authenticator
documentation](https://github.com/google/google-authenticator/wiki/Key-Uri-Format).

Example:

```erlang
Key = <<"Hello world">>,
Validator = totp_validator:init(Key, [{nb_digits, 6}]),
Issuer = <<"JobTeaser"/utf8>>,
AccountName = <<"bob@example.com"/utf8>>,
totp_validator:otpauth_uri(Validator, Issuer, AccountName).
```
