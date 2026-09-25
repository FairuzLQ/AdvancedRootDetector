# Device lab — Firebase Test Lab

Runs `CleanDeviceScanTest` (app/src/androidTest) on **real, stock phones** in Google's device
farm. Test Lab devices are not rooted, so every root indicator is a false positive and fails
the run. Workflow: `.github/workflows/device-lab.yml` (manual + weekly).

## Cost

The free **Spark** plan includes a daily Test Lab quota (physical and virtual device tests —
check the current numbers on the Firebase pricing page). The workflow defaults to 3 physical
devices per run and never runs on push, so it stays inside the free quota.

## One-time setup (≈5 minutes)

1. **Firebase project** — https://console.firebase.google.com → *Add project* (Spark plan,
   no billing needed). Analytics can be off.
2. **Enable the APIs** in the same Google Cloud project
   (https://console.cloud.google.com → *APIs & Services → Library*):
   - *Cloud Testing API*
   - *Cloud Tool Results API*
3. **Service account** — *IAM & Admin → Service Accounts → Create*:
   - Role: **Basic → Editor**. Test Lab uploads the APKs to its default results bucket,
     which grants access to the project's *basic* Editor/Owner roles only — granular roles
     such as *Firebase Test Lab Admin* + *Storage Admin* still fail with
     `storage.objects.create` denied (verified).
   - *Keys → Add key → JSON* → a `.json` file downloads.
4. **GitHub secret** — repo *Settings → Secrets and variables → Actions → New secret*:
   - Name: `FIREBASE_SERVICE_ACCOUNT`
   - Value: the full contents of the JSON file (the project id is read from it).
5. Run it: *Actions → Device Lab (Firebase Test Lab) → Run workflow* (once merged to `main`),
   or push a commit whose message contains `[device-lab]`.

Results (pass/fail per device, logcat with the `RDLAB` tag, videos) are in the Firebase
console under *Test Lab*, and the pass/fail table is in the workflow summary.

## Local run

```bash
./gradlew :app:connectedDebugAndroidTest   # on any connected phone/emulator
```
