# Telegram-Media-Downloader

Script for downloading media files from a given Telegram channel. The script uses Virustotal and ClamAV to evaluate whether the files downloaded contain malicious code.

## Setup
Install requirements using
```bash
pip install -r requirements.txt
````
Install ClamAV from https://www.clamav.net/

Update config.cfg with Telegram api-id and -hash, Virustotal api-key, and downloads-path.
