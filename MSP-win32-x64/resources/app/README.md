# MSPRetro - Client
This is the client embedding Flash Player to play [MSPRetro](https://mspretro.com).  
A MSPRetro browser version is in development.

## Requirements
- [NodeJS (tested with v20.16.0)](https://nodejs.org/en/)  
You have to install the dependencies with `npm install` before continue.

## Quick start

```powershell
npm install
npm start
```

If no MongoDB config is provided, the app starts with the local `msp-db.json` fallback so anyone cloning the repo can run it immediately.

## MongoDB database
The local server can use MongoDB instead of `msp-db.json`.

To use a private MongoDB connection, create a local `.env` file based on `.env.example`.

Example `.env`:

```env
MONGODB_URI=mongodb+srv://USERNAME:PASSWORD@HOST/?appName=msp-2016
MONGODB_DB=msp_2016
MONGODB_STATE_COLLECTION=state
```

The `.env` file is ignored by git, so passwords and private connection strings are not published in the repository.

PowerShell example for local MongoDB without `.env`:

```powershell
$env:MONGODB_URI="mongodb://127.0.0.1:27017"
$env:MONGODB_DB="msp_2016"
npm start
```

Open `http://127.0.0.1/api/db/status` to check if the server is using `mongodb` or the JSON fallback.

## Build for Windows
`npm run build-windows`

## Build for MacOS
`npm run build-darwin`
