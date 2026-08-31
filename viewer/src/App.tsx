import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { PipelineDiagram } from "@/components/PipelineDiagram"

function App() {
  return (
    <main className="mx-auto flex max-w-3xl flex-col gap-8 px-6 py-16">
      <header className="flex flex-col gap-2">
        <p className="font-mono text-xs uppercase tracking-[0.12em] text-muted-foreground">
          ARGUS
        </p>
        <h1 className="text-3xl font-medium tracking-tight">Detection Stories</h1>
      </header>

      <Card>
        <CardHeader>
          <CardTitle className="font-mono text-base">AgentTesla</CardTitle>
          <div className="flex flex-wrap gap-2 pt-1">
            <Badge variant="secondary">T1620</Badge>
            <Badge variant="secondary">T1055.012</Badge>
          </div>
        </CardHeader>
        <CardContent>
          <Button variant="outline" size="sm" asChild>
            <a href="./agenttesla.html">View Detection Story</a>
          </Button>
        </CardContent>
      </Card>

      <section className="flex flex-col gap-4">
        <h2 className="text-sm font-medium text-muted-foreground">Pipeline</h2>
        <PipelineDiagram />
      </section>
    </main>
  )
}

export default App
