# Aydo

The best anti virus, ever!!

## Server

The server is a simple C++ server that uses [drogon](https://github.com/drogonframework/drogon) to handle HTTP requests.

### Note about the server

Remember to change the following constants in the config.json file:

- Database
- JWT Secret

To your own constants!

Use [server/Server/config.example.json](server/Server/config.example.json) as the reference for the latest server config shape. The live file still needs machine-specific paths, credentials, and database values.


### Standard error message

```json
{
    "message": "Error message"
}
```

Along with a status code (e.g. 400 Bad Request).

### Routes

| Route | Method | Description |
|-------|--------|-------------|
| /api/auth/register | POST | Register a new user |
| /api/auth/login | POST | Login a user |
| /api/auth/refresh-token | POST | Refresh a user's access token |
| /api/auth/me | GET | Get the current user |

#### /api/auth/register

Expects a JSON body with the following fields:

- email
- nickname
- password

Returns a JSON body with the following fields:

- message
- accessToken
- refreshToken

or **standard error message**

#### /api/auth/login

Expects a JSON body with the following fields:

- email
- password

Returns a JSON body with the following fields:

- message
- accessToken
- refreshToken

or **standard error message**

#### /api/auth/refresh-token

Expects a JSON body with the following fields:

- refreshToken

Returns a JSON body with the following fields:

- accessToken

or **standard error message**

#### /api/auth/me

Expects a header with the following fields:

- Authorization: Bearer `<accessToken>`

Returns a JSON body with the following fields:

- nickname

or **standard error message**

## VMRunner

VMRunner is a simple tool that allows you to run a virtual machine in a sandbox environment.

### Note about the VMRunner

Do not edit source constants per machine.

Configure the sandbox runtime in [server/Server/config.json](server/Server/config.json) under `custom_config.sandbox`. Dynamic scanning now reads the VMware paths, guest credentials, shared-folder settings, and timeout values from that config and passes them into `VMRunner.exe` at launch.

An up-to-date example is available at [server/Server/config.example.json](server/Server/config.example.json).

The required keys are:

- `vmRunnerPath`
- `vmRunPath`
- `analysisVmPath`
- `sandboxesDirectoryPath`
- `vmStartMode`
- `guestUser`
- `guestPass`
- `guestSharedDir`
- `shareFileName`
- `pmHostPath`
- `pmGuestPath`
- `dllInjectorHostPath`
- `dllInjectorGuestPath`
- `processRunnerHostPath`
- `processRunnerGuestPath`
- `suspiciousWorkdirGuest`
- `vmPowerOnMaxRetries`
- `vmPowerOnSleepMs`
- `vmToolsMaxRetries`
- `vmToolsSleepMs`
- `vmShutdownGraceMs`

Validation commands:

- `VMRunner.exe --self-test` checks VM shutdown/startup sequencing and shared-folder error handling.
- `Server.exe --self-test` checks sandbox config parsing and sandbox log path resolution.

## Data

The data folder contains the file hashes database and the signatures database. It is not included with the repository, because the database is updated daily and is huge.

To update the database, run the following commands:

```bash
python scripts/update_file_hashes_db.py -d -e -p
python scripts/update_file_signatures_db.py -d -e -p
```

### Script Arguments

| Script | Argument | Short | Long | Description |
|--------|----------|-------|------|-------------|
| Both | Download | `-d` | `--download` | Download new database from URL |
| Both | Extract | `-e` | `--extract` | Extract the database file |
| Both | Parse | `-p` | `--parse` | Parse CSV to SQLite database |
| Both | Remove files | `-r` | `--remove_files` | Remove the leftover files (if exists) (zip, csv) |
| update_file_hashes_db.py | Custom CSV | | `--csv` | Custom CSV file name (default: file_hashes.csv) |
| update_file_hashes_db.py | Custom ZIP | | `--zip` | Custom ZIP file name (default: file_hashes.zip) |
| update_file_hashes_db.py | Custom DB | | `--db` | Custom SQLite database file name (default: file_hashes.db) |

### Data formats

#### File hashes

The database is organized in a table named "file_hashes" with the following columns:

| sha256 | name |
|--------|------|
| 0e306925a2ce33cb034c072708b5c39e0e306925a2ce33cb034c072708b5c39e | RansomwareExample |

#### In-file signatures

The in-file signatures are formatted this way (in a JSON file):

```json
{
    "AABB??BB": "RansomwareExample" // Meaning, AABB??BB is the signature, and RansomwareExample is the name
}
```

### Note about the database

Because CalmAV has blocked the option to download the database using a script (they added a captcha), you will need to download the database manually from the following URL:

<https://database.clamav.net/main.cvd>

Also, you have to download [clamav](https://github.com/Cisco-Talos/clamav) to extract the database file using their sigtool.exe (**just download the _zip_ file, and extract it to a folder, and then paste the sigtool.exe path into the script.**)

## License

MIT

## Desktop App (Electron)

The desktop console lives in `apps/desktop`. See `apps/desktop/README.md` for Bun-only run, build, and packaging instructions.
