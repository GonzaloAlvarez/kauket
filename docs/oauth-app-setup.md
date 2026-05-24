# Kauket OAuth app setup

Kauket falls back to the GitHub OAuth device flow when `gh` is not installed
or is authenticated with insufficient scopes. This requires a registered
GitHub OAuth App that exposes a client ID. There is no client secret in
device flow, so distributing the client ID inside the binary is intended.

## 1. Register the OAuth App

1. Sign in as `GonzaloAlvarez` and open
   `https://github.com/settings/applications/new`.
2. Fill in:
   - Application name: `kauket`
   - Homepage URL: `https://github.com/GonzaloAlvarez/kauket`
   - Authorization callback URL: `http://127.0.0.1/unused` (device flow ignores this)
3. After creating the app, open the app settings and click
   **Enable Device Flow**. Without this flag the device endpoint returns
   `device_flow_disabled`.
4. Copy the **Client ID** that GitHub shows. There is no client secret to
   record; device flow does not need one.

## 2. Required scopes

Kauket requests these scopes when it runs the device flow:

- Admin operations: `repo`, `admin:public_key`
- Client transient operations: `repo`

The OAuth app does not declare scopes; the running CLI passes them per
authorization request. The app only needs to exist and have device flow
enabled.

## 3. Embed the client ID at build time

The package `internal/githubauth` exposes the variable
`ClientID` (default `"PLACEHOLDER_OAUTH_CLIENT_ID"`). Inject the real
client ID at build time:

```sh
go build \
  -ldflags "-X 'github.com/gonzaloalvarez/kauket/internal/githubauth.ClientID=Iv1.XXXXXXXXXXXXXXXX'" \
  -o kauket ./cmd/kauket
```

Release builds should pull the client ID from a CI secret rather than
committing it to the repository.

## 4. Rotating the client ID

If the client ID needs to change, register a new OAuth App, rebuild
with the new value, and ship a new release. The old client ID stops
issuing tokens once the OAuth App is deleted in GitHub settings.
