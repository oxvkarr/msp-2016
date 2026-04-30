# MSPRetro - Client
This is the client embedding Flash Player to play [MSPRetro](https://mspretro.com).  
A MSPRetro browser version is in development.

## Requirements
- [NodeJS (tested with v20.16.0)](https://nodejs.org/en/)  
You have to install the dependencies with `npm install` before continue.

## MongoDB database
The local server can use MongoDB instead of `msp-db.json`.

PowerShell example for local MongoDB:

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
