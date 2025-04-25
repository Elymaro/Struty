# Struty

**Struty** is an automated auditing tool designed to detect known vulnerabilities in the implementation of the **Apache Struts** framework, particularly those leading to remote code execution (RCE). It relies on payloads specific to each vulnerability (S2-0XX) to test their presence on a target.

With the exception of vulnerability **S2-017**, all the vulnerabilities tested by Struty can lead to **remote code execution**.

---

## About Apache Struts

[Apache Struts](https://struts.apache.org/) is an open-source Java web framework that was widely used for its integration with Java EE and centralized action handling. It was often chosen in environments needing stability and built-in support for forms and validation.

However, several versions have presented serious vulnerabilities allowing remote code execution through OGNL (Object-Graph Navigation Language) injection, especially in misconfigured or unpatched versions.

---

## Exposed Debug Endpoints

Some versions of Struts expose debugging features via GET parameters. These may allow introspection, expression evaluation, or full RCE in specific contexts.

| Endpoint Test             | Parameter            | Indicator in Response           | Risk                                         |
| ------------------------- | -------------------- | ------------------------------- | -------------------------------------------- |
| `/target?debug=xml`       | `debug=xml`          | `<debug>` in body               | May expose internal object state             |
| `/target?debug=browser`   | `debug=browser`      | `debugTable` in body            | Could expose stack, vars, even RCE (DevMode) |
| `/target?debug=console`   | `debug=console`      | `OGNL Console` string           | Insecure expression evaluation               |
| `debug=command`           | `expression=1*2`     | Returns computed value (`2`)    | Strong sign of OGNL eval = RCE               |
| `/struts/webconsole.html` | with `debug=console` | `"Welcome to the OGNL console"` | Accessible OGNL console                      |

These are automatically tested by Struty prior to CVE-specific testing.

---

## Vulnerabilities Tested

| ID         | CVE            | Technical Summary                                                                 |
| ---------- | -------------- | --------------------------------------------------------------------------------- |
| S2-DevMode | -              | OGNL RCE via `debug=browser` when `devMode=true` and `object` param is evaluated. |
| S2-001     | CVE-2007-4556  | OGNL expressions evaluated via input fields when `altSyntax=true`.                |
| S2-003     | CVE-2008-6504  | Parameters with `#` allow context object modification.                            |
| S2-005     | CVE-2010-1870  | ParametersInterceptor allows OGNL context manipulation.                           |
| S2-008     | CVE-2012-0392  | CookieInterceptor mishandles OGNL-injected cookie names.                          |
| S2-012     | CVE-2013-1966  | OGNL injection via `includeParams` in `<a>` or `<url>` tags.                      |
| S2-013     | CVE-2013-2134  | OGNL in wildcard action mappings (`*`) evaluated unsafely.                        |
| S2-016     | CVE-2013-2251  | Exploits `redirect:` and `action:` prefixes to inject OGNL.                       |
| S2-017     | CVE-2013-2251  | Open redirect via OGNL expression in redirect URL.                                |
| S2-019     | CVE-2013-4310  | Bypass of security constraints via `action:` prefix.                              |
| S2-032     | CVE-2016-3081  | DMI allows code execution via `method:` prefix.                                   |
| S2-037     | CVE-2016-4438  | OGNL injection via REST plugin with crafted path params.                          |
| S2-045     | CVE-2017-5638  | RCE via `Content-Type` in `multipart/form-data` (Jakarta parser).                 |
| S2-053     | CVE-2017-12611 | OGNL injection via unescaped Freemarker tag expressions.                          |
| S2-057     | CVE-2018-11776 | OGNL in namespace/action part of URL (when mapping is misconfigured).             |
| S2-059     | CVE-2019-0230  | Double OGNL evaluation in tag attributes leads to RCE.                            |
| S2-061     | CVE-2020-17530 | Forced OGNL evaluation in tag attributes leads to RCE.                            |
| S2-066     | CVE-2023-50164 | Arbitrary file upload via crafted `fileFileName`, no path validation.             |
| S2-067     | CVE-2023-50164 | Variant of S2-066 exploiting alternative param structure (`top.fileFileName`).    |

---

## Installation

```
pip install -r requirements.txt
```

## Usage

Struts mainly use `.action`, `.do`, `.jsp` extension.

Execution :

```bash
python3 struty.py http://target.com/login/user.action
```

Execution with a proxy :

```bash
python3 struty.py -x http://127.0.0.1:8080 http://target.com/login/user.action
```

> When executed with a proxy, it is possible to retrieve easily a specific request / response by searching the pattern `X-Scan: S2-0XX` in the request headers

---

## Example

![image](https://github.com/user-attachments/assets/7f9feaff-86ef-4149-b4e0-e72259bfe548)
