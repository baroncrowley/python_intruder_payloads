# Python Intruder Payloads
This extension allows users to specify arbitrary Python2 scripts to generate or process Burp Intruder payloads.

When writing generator scripts, your script should place any generated payloads to use in `payloads` as a list of strings.

This generator script generates the numbers 1-10 using `range()`, converts them to strings using `map()`, and stores the result in `payloads`, which Burp will then use as the generated payloads:
```
payloads = map(str, range(10))
```

When writing processing scripts:
* `baseValue` is the value from the original request where the insertion point was specified
* `originalPayload` contains the payload without any processing applied
* `currentPayload` contains the payload after any processing that has already been performed
* Your script should place the processed payload in `payload` as a string

This processor script takes the unprocessed payload, reverses the order of the characters, and stores the result in `payload`, which Burp will then use as the processed payload:
```
payload = currentPayload[::-1]
```

CAUTION: Since these scripts run arbitrary code, take caution when running any script you don't trust.
