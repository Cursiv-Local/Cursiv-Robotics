# Your phone as a research instrument

No robot needed. Your phone records real sensor data with **phyphox** (free, RWTH Aachen University).
Your PC turns the recordings into signed, independently verifiable evidence and a research dossier
(Markdown and PDF) that Cursiv can import and write up.

The phone only records; nothing extra is installed on it, and Cursiv Robotics runs on your PC.

## 1. On the phone

1. Install **phyphox** (Android: Google Play; iPhone: App Store).
2. Pick a sensor. Good first choices:
   - **Pressure** (barometer, most mid- and high-end phones): air pressure. It changes with weather and with height.
   - **Location (GPS)**: position, height and speed, so other readings can be mapped.
   - **Light**: illuminance (lux).
   - (Accelerometer and magnetometer work too; high-rate sensors are reduced to 2 samples per second, and the full original stays attached.)
3. For a mapped survey, record **Location (GPS)** and **Pressure** as two recordings over the same walk (start them a few seconds apart). Readings get a location when a GPS fix is within 10 seconds.
4. Press ▶ to start, walk, then press ⏸.
5. Export with the ⋮ menu, then **Export Data**, then choose **CSV (Comma, decimal point)**. phyphox makes a `.zip`. Other CSV variants also work. Choose the zip, not the "minimal" single CSV: the zip contains the clock mapping (`meta/time.csv`) that turns the recording into real times.
6. Send the zip to your PC (email, cloud drive, USB cable, or Nearby Share or AirDrop).

### iPhone notes

- Every iPhone since the iPhone 6 has a barometer, so **Pressure** works; **Location (GPS)** needs Location access for phyphox (Settings > Privacy & Security > Location Services > phyphox > While Using).
- Export: ⋮ (or the share icon) > **Export Data** > **CSV (Comma, decimal point)** > share the `.zip`.
- To get the zip onto a Windows PC: email it to yourself, save it to **iCloud Drive** or **OneDrive** (both have Windows apps), or connect the iPhone with a cable and copy it in the Windows Files/Apple Devices app. (AirDrop does not work with Windows.)
- The dossier shows Apple's hardware model id (for example `iPhone14,5`) and no sensor part names: phyphox on iOS does not export them.

## 2. On the PC (once)

Install Rust (https://rustup.rs) and Python 3.11+, then in PowerShell:

```powershell
git clone https://github.com/Cursiv-Local/Cursiv-Robotics.git
cd Cursiv-Robotics
cargo build --release
py -m pip install cryptography
```

## 3. Turn a recording into evidence and a dossier

```powershell
cd python
py -m cursiv_field run "C:\Users\you\Downloads\Location (GPS) 2026-11-05.zip" "C:\Users\you\Downloads\Pressure 2026-11-05.zip" `
   --mission creek-walk-1 --title "Creek walk: pressure and position" --notes "Overcast, light wind; walked the east path."
```

It prints the verification verdicts and where the files are, under `%USERPROFILE%\CursivField\reports\<mission>-<time>\`:

| File | What it is |
|---|---|
| `dossier.md` | The research dossier, for Cursiv |
| `dossier.pdf` | The same, as a PDF (made with Edge or Chrome, already on Windows) |
| `dossier.html` | The same, for a browser |
| `data.csv` | Every observation with its id, time, location and value |
| `verification.json` | The full machine-readable verification |

The signed evidence package (a BagIt bag) is in `%USERPROFILE%\CursivField\store\exports\`.
Importing the same recording again is refused, so nothing is duplicated.

## 4. Give it to Cursiv

In Cursiv's chat: `add document C:\Users\you\CursivField\reports\...\dossier.pdf` (or `dossier.md`).
Then ask it to draft a paper from the dossier.

The dossier starts with rules for any writer, human or AI: use only cited values, keep the
Known/Inferred/Assumed/Unknown labels, never upgrade an Unknown, and keep the verification and
limitations sections. Every statistic in it is a signed derived result that the verifier
re-computed from the cited readings.

## What the dossier will honestly say

- *Unknown:* calibration and uncertainty of phone sensors (phones do not report them), and whether the phone clock was synchronized.
- *Known:* custody. The phone does not sign data; the recording is signed when your PC imports it, and the original zip is attached by SHA-256.
- Integrity and authenticity show the data is unchanged and complete, not that it is correct.

To make the science stronger: compare the barometer with a nearby official weather station
(the difference is a real calibration check), note the weather, and record a few minutes standing
still before walking.
