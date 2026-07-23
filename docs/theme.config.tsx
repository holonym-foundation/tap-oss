import type { DocsThemeConfig } from 'nextra-theme-docs'
import { useConfig } from 'nextra-theme-docs'

function Head() {
  const { title } = useConfig()
  return (
    <>
      <title>{title ? `${title} – TAP` : 'Tool Authorization Protocol'}</title>
      <link
        rel="icon"
        href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🔐</text></svg>"
      />
    </>
  )
}

const config: DocsThemeConfig = {
  logo: <strong>Tool Authorization Protocol</strong>,
  project: {
    link: 'https://github.com/holonym-foundation/tap-oss',
  },
  docsRepositoryBase: 'https://github.com/holonym-foundation/tap-oss/tree/master/docs',
  footer: {
    content: 'Tool Authorization Protocol - Credential isolation for AI agents',
  },
  head: Head,
}

export default config
