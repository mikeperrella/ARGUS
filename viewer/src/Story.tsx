import { useMemo, type ReactNode } from "react"
import ReactMarkdown, { type Components } from "react-markdown"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Separator } from "@/components/ui/separator"
import storyRaw from "../../stories/detection_story_agenttesla_01.md?raw"

const SCREENSHOT_BASE = `${import.meta.env.BASE_URL}screenshots/`

interface StorySection {
  heading: string
  body: string
}

function parseStory(raw: string): { hash: string; sections: StorySection[] } {
  const [titleLine, ...rest] = raw.trim().split("\n")
  const hash = titleLine.split("—").pop()?.trim() ?? ""
  const body = rest.join("\n").replace(/^\n+/, "")
  const sections = body.split(/\n## /).map((chunk) => {
    const [heading, ...bodyLines] = chunk.replace(/^## /, "").split("\n")
    return { heading: heading.trim(), body: bodyLines.join("\n").trim() }
  })
  return { hash, sections }
}

const markdownComponents: Components = {
  p: ({ children }) => (
    <p className="text-sm leading-relaxed text-muted-foreground">{children}</p>
  ),
  strong: ({ children }) => (
    <strong className="font-medium text-foreground">{children}</strong>
  ),
  code: ({ className, children }) => {
    if (className) {
      return <code className="font-mono text-xs text-foreground">{children}</code>
    }
    return (
      <code className="rounded bg-muted px-1 py-0.5 font-mono text-xs text-foreground">
        {children}
      </code>
    )
  },
  pre: ({ children }) => (
    <pre className="overflow-x-auto rounded-md border border-border bg-card p-4">
      {children}
    </pre>
  ),
}

function Figure({
  src,
  alt,
  caption,
}: {
  src: string
  alt: string
  caption: ReactNode
}) {
  return (
    <figure className="flex flex-col gap-2 overflow-hidden rounded-md border border-border">
      <img src={src} alt={alt} className="w-full" />
      <figcaption className="px-3 pb-3 text-xs text-muted-foreground">
        {caption}
      </figcaption>
    </figure>
  )
}

function Story() {
  const { hash, sections } = useMemo(() => parseStory(storyRaw), [])

  return (
    <main className="mx-auto flex max-w-3xl flex-col gap-8 px-6 py-16">
      <Button variant="ghost" size="sm" asChild className="w-fit">
        <a href="./index.html">← Index</a>
      </Button>

      <header className="flex flex-col gap-2">
        <p className="font-mono text-xs uppercase tracking-[0.12em] text-muted-foreground">
          Detection Story
        </p>
        <h1 className="text-2xl font-medium tracking-tight">AgentTesla</h1>
        <div className="flex flex-wrap gap-2 pt-1">
          <Badge variant="secondary">T1620</Badge>
          <Badge variant="secondary">T1055.012</Badge>
        </div>
        <p className="pt-1 font-mono text-xs text-muted-foreground">SHA256 {hash}</p>
      </header>

      <Figure
        src={`${SCREENSHOT_BASE}sample-hash-verification.png`}
        alt="certutil -hashfile output matching the sample's SHA256 hash"
        caption={
          <>
            Sample hash verified via <code className="font-mono">certutil</code>.
          </>
        }
      />

      {sections.map((section, index) => (
        <section key={section.heading} className="flex flex-col gap-3">
          <h2 className="flex items-baseline gap-2 text-sm font-medium text-foreground">
            <span className="font-mono text-xs text-muted-foreground">
              {String(index + 1).padStart(2, "0")}
            </span>
            {section.heading}
          </h2>
          <ReactMarkdown components={markdownComponents}>
            {section.body}
          </ReactMarkdown>

          {section.heading === "Raw Findings" && (
            <Figure
              src={`${SCREENSHOT_BASE}capa-attck-mbc-capability.png`}
              alt="capa's rendered ATT&CK, MBC, and Capability tables for this sample"
              caption="capa's rendered ATT&CK Tactic/Technique, MBC, and Capability output for this sample."
            />
          )}

          {section.heading === "The Tuned Rule" && (
            <Figure
              src={`${SCREENSHOT_BASE}tuned-rule-accepted.png`}
              alt="candidate_v1.yar and decisions_log.json showing the accepted decision"
              caption={
                <>
                  <code className="font-mono">decisions_log.json</code> recording the
                  accept decision for this rule.
                </>
              }
            />
          )}
        </section>
      ))}

      <Separator />

      <section className="flex flex-col gap-3">
        <h2 className="text-sm font-medium text-foreground">Lab Environment</h2>
        <div className="grid gap-4 sm:grid-cols-2">
          <Figure
            src={`${SCREENSHOT_BASE}defender-realtime-off.png`}
            alt="Windows Security showing Defender real-time protection turned off"
            caption="Defender real-time protection disabled on the analysis VM."
          />
          <Figure
            src={`${SCREENSHOT_BASE}tool-install-listing.png`}
            alt="C:\Tools directory listing showing capa, DIE, floss, Ghidra, x64dbg"
            caption="Tooling installed on the analysis VM."
          />
        </div>
      </section>
    </main>
  )
}

export default Story
