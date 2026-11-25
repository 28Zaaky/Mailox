import ModuleBase from './_ModuleBase'

export default function SMTPSecurity() {
  return (
    <ModuleBase
      engine="smtp_security"
      title="SMTP Security"
      subtitle="SMTP security findings"
      description="STARTTLS enforcement, cleartext AUTH without TLS, open relay detection, TLS certificate validity (expiry, hostname mismatch, self-signed), deprecated TLS versions (TLSv1.0/1.1), weak cipher suites (RC4, DES, NULL, EXPORT), and VRFY/EXPN user enumeration."
    />
  )
}
