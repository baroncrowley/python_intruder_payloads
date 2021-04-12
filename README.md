# Python Intruder Payloads
This extension allows users to specify arbitrary Python2 scripts to generate or process Burp Intruder payloads.

When writing generator scripts, your script should place any generated payloads to use in `payloads` as a list of strings.

When writing processing scripts, `currentPayload` contains the unprocessed payload. Your script should place the processed payload in `payload` as a string.

Since these scripts run arbitrary code, take caution when running any script you don't trust.
