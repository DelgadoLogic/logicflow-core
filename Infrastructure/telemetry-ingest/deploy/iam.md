# IAM and secrets (least privilege)

Nothing here is applied automatically except by `deploy.ps1 -Execute`. Review first.

## Identities

| Service account | Used by | Roles |
| --- | --- | --- |
| `lf-ingest@<project>` | Cloud Run service `lf-telemetry-ingest` | `roles/storage.objectAdmin` **on the telemetry bucket only** (writes parts/stats/tombstones, rewrites partitions for erasure); `roles/secretmanager.secretAccessor` on `lf-ingest-keys` and `lf-admin-token` only |
| `lf-digest@<project>` | Cloud Run job `lf-telemetry-digest` | same bucket-scoped `objectAdmin` (reads events, writes digests, purges erased installs); accessor on the same two secrets (not strictly required for the job, harmless) |
| `lf-scheduler@<project>` | Cloud Scheduler | `roles/run.invoker` **on the job** `lf-telemetry-digest` only |
| Analysts / agents | `scripts\fetch-digest.ps1`, `lf-telemetry.js`, `bq` | `roles/storage.objectViewer` on the bucket; `roles/bigquery.jobUser` on the project; `roles/bigquery.dataViewer` on the dataset. External tables are read with the **caller's** credentials, so the caller needs bucket read access too |

`objectAdmin` is required (not `objectCreator`) because the erasure path overwrites and deletes objects. Do not grant
project-level storage roles. The Cloud Run service is public (`--allow-unauthenticated`) because the desktop app cannot hold
Google credentials; protection is HMAC signing, consent gating, schema validation, size limits and rate limits.
`/internal/digest` is token protected and is unused when you use the Cloud Run job.

Nobody should hold `roles/storage.admin` / `roles/owner` for day-to-day operation. The deploying identity needs
`run.admin`, `iam.serviceAccountAdmin`, `storage.admin` (bucket create), `secretmanager.admin`, `artifactregistry.admin`,
`cloudbuild.builds.editor`, `cloudscheduler.admin`, `bigquery.admin`, `serviceusage.serviceUsageAdmin` and
`iam.serviceAccountUser` on the three accounts. Prefer a temporary elevated session over permanent grants.

## Secrets (values are never created by the script)

| Secret | Content | Rotation |
| --- | --- | --- |
| `lf-ingest-keys` | one or more build HMAC keys, comma separated: `newKey,oldKey` | add the new key first, ship builds, drop the old key later; Cloud Run reads `:latest` at instance start, so redeploy/new revision after changing |
| `lf-admin-token` | random 32+ byte token for `POST /internal/digest` | rotate any time |

Create a version without echoing it to the terminal history:

```powershell
$k = [Convert]::ToBase64String((1..32 | ForEach-Object { [byte](Get-Random -Max 256) }))
$k | gcloud secrets versions add lf-ingest-keys --data-file=- --project <project>
```

The build key is embedded in the release binary; treat it as a rotating spam gate, not a confidential credential.

## Hosting

Firebase Hosting needs permission to invoke the Cloud Run service. `--allow-unauthenticated` already satisfies it; if you later
lock the service down, grant Hosting's service agent `roles/run.invoker`.
