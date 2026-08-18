Set-Location 'e:\tanchuang'
npx tsc -p tsconfig.main.json
Start-Process -FilePath 'node_modules\.bin\electron.cmd' -ArgumentList '.'
Write-Host 'dev electron started'
