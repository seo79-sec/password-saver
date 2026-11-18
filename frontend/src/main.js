import './style.css'
import App from './App.svelte'
import { getThemeController } from './ui.js'

// Reuse the head bootstrap's controller; this is also a safe mount fallback.
getThemeController()

const app = new App({
  target: document.getElementById('app')
})

export default app
