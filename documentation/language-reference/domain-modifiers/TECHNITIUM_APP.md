---
name: TECHNITIUM_APP
parameters:
  - name
  - appName
  - classPath
  - recordData
  - modifiers...
parameter_types:
  name: string
  appName: string
  classPath: string
  recordData: string
  "modifiers...": RecordModifier[]
provider: TECHNITIUM
---

`TECHNITIUM_APP` creates a Technitium DNS App record, which hands a query off to an installed [DNS app](https://blog.technitium.com/2021/03/creating-and-running-dns-apps-on.html) - for example, the Split Horizon app included with Technitium - instead of answering it directly. Technitium calls this record type `APP`.

`appName` is the name of the installed app, exactly as it appears in the Technitium web console's Apps page. `classPath` selects the app's DNS App record request handler class. `recordData` is the app-specific configuration - usually a JSON string - whose format is defined by the app itself; see the app's own documentation for what it expects.

Only one `APP` record can exist at a label, and it takes priority over the DNS App's own `ApplicationRecordDataTemplate` prompt in the web console. Technitium does not check an `APP` record against any `A`/`AAAA` records also present at the label - those take precedence, so remove them if the app is meant to answer the query.

See the [Technitium provider page](../../provider/technitium.md) for more about this provider.

{% code title="dnsconfig.js" %}
```javascript
D("example.com", REG_MY_PROVIDER, DnsProvider(DSP_TECHNITIUM),
    // Answer "host.example.com" differently depending on the querying
    // client's network, using the built-in Split Horizon app.
    TECHNITIUM_APP("host", "Split Horizon", "SplitHorizon.SimpleAddress", JSON.stringify({
        "192.168.1.0/24": ["192.168.1.10"],
        "0.0.0.0/0": ["203.0.113.10"],
    })),
);
```
{% endcode %}
