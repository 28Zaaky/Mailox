import ModuleBase from './_ModuleBase'

export default function SMTPDiscovery() {
  return (
    <ModuleBase
      engine="smtp_discovery"
      title="SMTP Discovery"
      subtitle="SMTP discovery findings"
      description="Discovered mail servers and open relay issues across all scanned domains."
    />
  )
}
