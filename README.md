# Duo Authenticator Plugin for Jupyter #

Simple Duo Authenticator Plugin for JupyterHub

## Requirements and Limitations ##

This plugin adds Duo **secondary authentication**.  The primary authentication
is done using another Authenticator.  By default, this is the standard PAM
Authenticator.  Any other custom Authenticator that functions when used as
the sole authenticator via `c.JupyterHub.authenticator_class` should work, but
only the PAMAuthenticator has been tested.

It is recommended to setup and test whichever primary authenticator will be used
first to ensure it's functioning before installing this plugin.

## Installation ##

Install from Github using pip:

```
pip install git+https://github.com/unlhcc/jupyter-duoauthenticator.git
```

### Create a Duo application ###

Add a new Application of type Web SDK in the Duo Control Panel.  Make a note of
the Integration Key, Secret Key, and API hostname.

### Generate the akey ###

The akey is a generated string used to sign requests and is kept secret from Duo.
To generate the akey using Python, run

```python
import os, hashlib
print hashlib.sha1(os.urandom(32)).hexdigest()
```

More details can be found in the [Duo documentation](https://duo.com/docs/duoweb).

## Usage ##

Enable the authenticator by setting the following in your `jupyter_config.py`:

```python
import duoauthenticator
c.JupyterHub.authenticator_class = 'duoauthenticator.DuoAuthenticator'
```

### Required configuration ###

The following configuation options must be set:

#### `c.DuoAuthenticator.ikey` ####

The Integration key from the Duo Application Details:

```python
c.DuoAuthenticator.ikey = '<my ikey>'
```

#### `c.DuoAuthenticator.skey` ####

The Secret key from the Duo Application Details:

```python
c.DuoAuthenticator.skey = '<my skey>'
```

#### `c.DuoAuthenticator.akey` ####

The generated akey:

```python
c.DuoAuthenticator.akey = '<my akey>'
```

#### `c.DuoAuthenticator.apihost` ####

The API hostname from the Duo Application Details:

```python
c.DuoAuthenticator.apihost = 'api-XXXXX.duosecurity.com'
```

### Optional configuration ###

#### `c.DuoAuthenticator.primary_auth_class` ####

The class to use for the primary authentication.  Default is the built-in
PAMAuthenticator, i.e.

```python
c.DuoAuthenticator.primary_auth_class = 'jupyterhub.auth.PAMAuthenticator'
```

#### `c.DuoAuthenticator.duo_custom_html` ####

Custom html as a Unicode string to use for the Duo auth page.  Default is an
empty string, which will use the included `duo.html` template:

```python
c.DuoAuthenticator.duo_custom_html=''
```

Must contain at minimum an iframe with `id='duo_iframe'`, as well as `data-host`
and `data-sig-request` template attributes to be populated.  See
the [Duo documentation](https://duo.com/docs/duoweb#appendices) for more details
on the iframe configuration.
