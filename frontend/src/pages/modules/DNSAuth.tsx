import ModuleBase from './_ModuleBase'

export default function DNSAuth() {
  return (
    <ModuleBase
      engine="dns_auth"
      title="DNS Authentication"
      subtitle="DNS authentication findings"
      description="SPF, DKIM, DMARC, and MTA-STS configuration issues for all scanned domains."
    />
  )
}
