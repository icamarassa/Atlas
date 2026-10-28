#!/bin/sh
set -eu

# Install mounted LDAPS trust anchors before dropping privileges.
update-ca-certificates

# Keep the mounted PFX private, but make it readable by the unprivileged API process.
runtime_dir=/run/atlas-ti
mkdir -p "$runtime_dir"
cp /run/secrets/atlas-ti-dp.pfx "$runtime_dir/atlas-ti-dp.pfx"
chown "$APP_UID" "$runtime_dir" "$runtime_dir/atlas-ti-dp.pfx"
chmod 700 "$runtime_dir"
chmod 400 "$runtime_dir/atlas-ti-dp.pfx"
export DataProtection__KeyEncryptionCertificatePath="$runtime_dir/atlas-ti-dp.pfx"

exec gosu "$APP_UID" dotnet api.dll
