# 013 — Fleet backups (push to backup01.scl04)

Status: live for NetBox, 2026-11-10.

## Problem

Nothing in the fleet had an off-host copy. Hypervisors vzdump to their own
local disk (pve01.scl04 not even that), and app state — the NetBox database
above all — existed in exactly one place.

## Design

Each app pushes its own backup set; there is no central backup server pulling
with fleet-wide credentials.

- **Target:** `backup01.scl04` (PVE VM 109). Data lives on a thin 500G zvol on
  pve01.scl04's raidz2 `tank`, ext4 `LABEL=backup` at `/srv/backup`; grow with
  `qm resize 109 scsi1 +NG` and `resize2fs`.
- **Client** (`backup_push` group, `roles/backup_push`): a systemd timer runs
  `sfmix-backup-push`, which runs the host's `backup_push_dump_script` (for
  example `pg_dump`) into `dump/`, tars that plus `backup_push_paths` into one
  `<name>-<UTC stamp>.tar.zst`, and rsyncs it over SSH.
- **Add-only:** each client has its own account on the target, `bk-<name>`, with
  a root-owned `authorized_keys` that forces
  `rrsync -wo -no-del -no-overwrite -munge <root>/<name>/incoming`. The client
  can't read, list, delete or overwrite anything, so a compromised app can't
  destroy its own history.
- **Seal** (`roles/backup_target`, every 10 min, as root): verifies finished
  uploads and moves them into root-only `archive/`, or into `quarantine/` if
  they fail (see Integrity). It prunes bundles past 30 days but always keeps
  the newest 10, and writes `sfmix_backup_*` textfile metrics.
- **Verify** (weekly, as root): re-checks every sealed bundle's zstd checksum.
- **Alerts** (`rules/backup.rules.yml`):
  - `BackupStale`: one rule per client. Fires when the newest bundle is older
    than `backup_push_max_age_hours` (default 14h, with a 6-hourly schedule),
    or when there is none.
  - `BackupSealerStale` / `BackupVerifyStale`: a timer has stopped completing.
  - `BackupQuarantined`: an upload failed verification.
  - `BackupArchiveCorrupt`: a sealed bundle fails its checksum.

## Integrity

How each stage knows its copy is complete and correct:

1. **Dump** (client): the script runs with `set -e`, so a failed `pg_dump` or
   `tar` aborts the push. `backup_push_verify_script` then checks the dump
   itself before bundling. For NetBox that is a full `pg_restore` to
   `/dev/null`: `--list` only reads the table of contents, while a full restore
   decompresses every data block.
2. **Transfer** (rsync): the receiver writes to a dot-prefixed temp file. It
   compares a whole-file checksum with the sender's, re-sending once on a
   mismatch, and only then renames the file into place atomically. If the
   connection drops, the receiver deletes the temp file. Tested 2026-11-10:
   SIGTERM and SIGKILL of the client mid-transfer left nothing in `incoming/`.
   The push script never passes `--partial` or `--inplace`, which would let a
   partial file appear under its real name.
3. **Seal** (target): a non-dot file in `incoming/` is a complete upload. The
   seal job first makes it root-owned and read-only, then runs `zstd -t`. The
   zstd frame checksum (XXH64) was computed over the content when the bundle
   was made on the client, so this check is end to end. It also catches a
   client that sent garbage or a partial file on purpose: rrsync can't forbid
   `--partial`. Failures go to `quarantine/` and are never archived.
   Temp files idle for more than a day are dead (only a crashed receiver
   leaves them) and are deleted.
4. **At rest**: the weekly verify re-runs `zstd -t` over the archive. The zvol
   underneath is also covered by ZFS checksums and the monthly scrub.

The client pins the target's host key (`/etc/ssh/sfmix_backup_known_hosts`),
and the target learns the client's key in the same playbook run
(`deploy_backups.playbook.yml`: client keys → target → client timers).

## Adding an app

Put the host in `backup_push`, then set `backup_push_paths` /
`backup_push_excludes` / `backup_push_dump_script` /
`backup_push_verify_script` in its group_vars, then run
`deploy_backups.playbook.yml`. If the host is outside the UFW admin allow-list,
add its addresses to `backup_push_source_addrs`.

## Restore (NetBox)

On the target, as root, pick a bundle in `/srv/backup/netbox.sfo02/archive/`
and copy it to the restore host. Then:

    tar --zstd -xf netbox.sfo02-<stamp>.tar.zst
    # srv/netbox/shared/: configuration.py, generated_secret_key,
    #   generated_secret_pepper (API tokens are useless without it), media/, scripts/
    sudo -u postgres createdb -O netbox netbox_restore
    sudo -u postgres pg_restore -d netbox_restore --no-owner --role=netbox dump/netbox.pgdump

## Limits

- `backup01` shares the `tank` pool with pve01.scl04's own guests. It is
  off-site for sfo/fmt sources, but only protects scl04 sources against
  mistakes, not against losing the host. A second copy elsewhere is future work.
- `tank` is 8 aged ST4000DM000 drives in raidz2, and nothing alerts on pool
  or SMART state yet.
