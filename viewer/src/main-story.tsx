import { StrictMode } from "react"
import { createRoot } from "react-dom/client"
import "./index.css"
import Story from "./Story.tsx"

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <Story />
  </StrictMode>,
)
