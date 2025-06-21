import { useState } from 'react'
import reactLogo from './assets/react.svg'
import viteLogo from '/vite.svg'
import './App.css'
import Hibrida from "../src/Hibrida.jsx"

function App() {
  const [count, setCount] = useState(0)

  return (
    <>
    <Hibrida/>
    </>
  )
}

export default App
