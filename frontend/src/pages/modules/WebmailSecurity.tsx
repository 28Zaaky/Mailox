import ModuleBase from './_ModuleBase'

export default function WebmailSecurity() {
  return (
    <ModuleBase
      engine="webmail"
      title="Webmail & TLS"
      subtitle="Webmail security and transport findings"
      description="Exposed webmail interfaces, insecure headers, version disclosure, HSTS enforcement, HTTPS certificate issues, and mixed content on webmail deployments."
    />
  )
}
